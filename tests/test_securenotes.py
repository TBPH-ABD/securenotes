"""Tests for securenotes — the security controls, not the note-taking.

Each test names the attack it proves is blocked.
"""
from __future__ import annotations

import http.cookies
import os
import re
import secrets
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from datetime import timedelta
from http.server import ThreadingHTTPServer
from unittest import mock

import securenotes
from securenotes import (Database, hash_password, make_handler, token_digest,
                         validate_registration)

# Real PBKDF2 at 600k iterations costs ~0.3s per call, which would make this
# suite unusable. Logic is identical at a lower count; the production value is
# asserted separately in TestPasswordHashing.
FAST_ITERATIONS = 1_000


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stops urllib following 303s, so the redirect itself can be asserted on."""

    def redirect_request(self, *args, **kwargs):
        return None


class DatabaseTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(os.path.join(self._tmp.name, "test.db"))
        self._patch = mock.patch.object(securenotes, "PBKDF2_ITERATIONS",
                                        FAST_ITERATIONS)
        self._patch.start()

    def tearDown(self):
        self._patch.stop()
        self._tmp.cleanup()


class TestPasswordHashing(unittest.TestCase):
    def test_production_iteration_count_meets_owasp_guidance(self):
        self.assertGreaterEqual(securenotes.PBKDF2_ITERATIONS, 600_000)

    def test_same_password_different_salt_gives_different_hash(self):
        """Per-user salts are what defeat rainbow tables."""
        a = hash_password("same-password", secrets.token_bytes(16), FAST_ITERATIONS)
        b = hash_password("same-password", secrets.token_bytes(16), FAST_ITERATIONS)
        self.assertNotEqual(a, b)

    def test_same_password_same_salt_is_deterministic(self):
        salt = secrets.token_bytes(16)
        self.assertEqual(hash_password("pw", salt, FAST_ITERATIONS),
                         hash_password("pw", salt, FAST_ITERATIONS))

    def test_hash_does_not_contain_the_password(self):
        digest = hash_password("plaintext", b"0" * 16, FAST_ITERATIONS)
        self.assertNotIn(b"plaintext", digest)


class TestSessionTokenStorage(unittest.TestCase):
    def test_token_is_stored_hashed(self):
        """A database leak must not hand the attacker live sessions."""
        token = "a-session-token"
        self.assertNotEqual(token_digest(token), token)
        self.assertEqual(len(token_digest(token)), 64)

    def test_digest_is_deterministic(self):
        self.assertEqual(token_digest("x"), token_digest("x"))


class TestValidation(unittest.TestCase):
    def test_valid_registration_passes(self):
        self.assertEqual(
            validate_registration("salah", "a-long-enough-passphrase",
                                  "a-long-enough-passphrase"), [])

    def test_short_username_rejected(self):
        self.assertTrue(validate_registration("ab", "a" * 20, "a" * 20))

    def test_username_with_invalid_characters_rejected(self):
        self.assertTrue(validate_registration("bad user!", "a" * 20, "a" * 20))

    def test_short_password_rejected(self):
        errors = validate_registration("salah", "short", "short")
        self.assertTrue(any("12" in e for e in errors))

    def test_mismatched_confirmation_rejected(self):
        errors = validate_registration("salah", "a" * 20, "b" * 20)
        self.assertTrue(any("match" in e for e in errors))


class TestUserStorage(DatabaseTestCase):
    def test_user_can_be_created_and_found(self):
        user_id = self.db.create_user("salah", "a-long-passphrase")
        self.assertIsNotNone(user_id)
        self.assertEqual(self.db.get_user("salah")["id"], user_id)

    def test_duplicate_username_is_refused(self):
        self.db.create_user("salah", "a-long-passphrase")
        self.assertIsNone(self.db.create_user("salah", "another-passphrase"))

    def test_password_is_never_stored_in_plaintext(self):
        self.db.create_user("salah", "my-secret-passphrase")
        row = self.db.get_user("salah")
        self.assertNotIn(b"my-secret-passphrase", bytes(row["password_hash"]))

    def test_unknown_user_returns_none(self):
        self.assertIsNone(self.db.get_user("ghost"))

    def test_failure_count_locks_the_account(self):
        user_id = self.db.create_user("salah", "a-long-passphrase")
        self.db.register_failure(user_id, securenotes.MAX_FAILED_LOGINS)
        self.assertIsNotNone(self.db.get_user("salah")["locked_until"])

    def test_clearing_failures_unlocks(self):
        user_id = self.db.create_user("salah", "a-long-passphrase")
        self.db.register_failure(user_id, securenotes.MAX_FAILED_LOGINS)
        self.db.clear_failures(user_id)
        row = self.db.get_user("salah")
        self.assertIsNone(row["locked_until"])
        self.assertEqual(row["failed_attempts"], 0)


class TestSessions(DatabaseTestCase):
    def test_session_round_trips(self):
        user_id = self.db.create_user("salah", "a-long-passphrase")
        token, csrf = self.db.create_session(user_id)
        row = self.db.get_session(token)
        self.assertEqual(row["user_id"], user_id)
        self.assertEqual(row["csrf_token"], csrf)

    def test_each_session_gets_a_distinct_token(self):
        """A fresh token per login is what defeats session fixation."""
        user_id = self.db.create_user("salah", "a-long-passphrase")
        first, _ = self.db.create_session(user_id)
        second, _ = self.db.create_session(user_id)
        self.assertNotEqual(first, second)

    def test_unknown_token_is_rejected(self):
        self.assertIsNone(self.db.get_session("not-a-real-token"))

    def test_destroyed_session_is_rejected(self):
        user_id = self.db.create_user("salah", "a-long-passphrase")
        token, _ = self.db.create_session(user_id)
        self.db.destroy_session(token)
        self.assertIsNone(self.db.get_session(token))

    def test_expired_session_is_rejected(self):
        user_id = self.db.create_user("salah", "a-long-passphrase")
        with mock.patch.object(securenotes, "SESSION_LIFETIME",
                               timedelta(seconds=-1)):
            token, _ = self.db.create_session(user_id)
        self.assertIsNone(self.db.get_session(token))

    def test_purge_keeps_live_sessions(self):
        user_id = self.db.create_user("salah", "a-long-passphrase")
        with mock.patch.object(securenotes, "SESSION_LIFETIME",
                               timedelta(seconds=-1)):
            self.db.create_session(user_id)
        live, _ = self.db.create_session(user_id)
        self.db.purge_expired_sessions()
        self.assertIsNotNone(self.db.get_session(live))


class TestNoteAuthorization(DatabaseTestCase):
    def setUp(self):
        super().setUp()
        self.victim = self.db.create_user("victim", "a-long-passphrase")
        self.attacker = self.db.create_user("attacker", "another-passphrase")
        self.db.add_note(self.victim, "Private", "victim's secret")

    def note_id(self) -> int:
        return self.db.list_notes(self.victim)[0]["id"]

    def test_owner_sees_their_note(self):
        self.assertEqual(len(self.db.list_notes(self.victim)), 1)

    def test_other_user_sees_nothing(self):
        """Notes are scoped by user_id — no cross-user reads."""
        self.assertEqual(self.db.list_notes(self.attacker), [])

    def test_attacker_cannot_delete_another_users_note(self):
        """IDOR: guessing the note id must not be enough to delete it."""
        self.assertFalse(self.db.delete_note(self.note_id(), self.attacker))
        self.assertEqual(len(self.db.list_notes(self.victim)), 1)

    def test_owner_can_delete_their_own_note(self):
        self.assertTrue(self.db.delete_note(self.note_id(), self.victim))
        self.assertEqual(self.db.list_notes(self.victim), [])

    def test_sql_injection_in_a_note_is_stored_as_data(self):
        """Parameterised queries: the payload is text, never executed SQL."""
        payload = "'; DROP TABLE notes; --"
        self.db.add_note(self.victim, payload, payload)
        titles = [n["title"] for n in self.db.list_notes(self.victim)]
        self.assertIn(payload, titles)
        self.assertEqual(len(self.db.list_notes(self.victim)), 2)


class LiveServerTestCase(unittest.TestCase):
    """Runs the real application over HTTP on an ephemeral port."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._patch = mock.patch.object(securenotes, "PBKDF2_ITERATIONS",
                                        FAST_ITERATIONS)
        self._patch.start()
        self.db = Database(os.path.join(self._tmp.name, "live.db"))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0),
                                          make_handler(self.db, False))
        self.server.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       args=(0.01,), daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self._patch.stop()
        self._tmp.cleanup()

    def post(self, path: str, data: str, cookie: str | None = None):
        """POST form data without following redirects."""
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookie:
            headers["Cookie"] = cookie
        request = urllib.request.Request(self.base + path,
                                         data=data.encode(), headers=headers)
        opener = urllib.request.build_opener(NoRedirect)
        try:
            with opener.open(request, timeout=5) as resp:
                return (resp.status, resp.headers,
                        resp.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            headers_out = exc.headers
            exc.close()
            return exc.code, headers_out, body

    def get(self, path: str, cookie: str | None = None):
        headers = {"Cookie": cookie} if cookie else {}
        request = urllib.request.Request(self.base + path, headers=headers)
        opener = urllib.request.build_opener(NoRedirect)
        try:
            with opener.open(request, timeout=5) as resp:
                return resp.status, resp.headers, resp.read().decode()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            headers_out = exc.headers
            exc.close()
            return exc.code, headers_out, body

    @staticmethod
    def session_of(headers) -> str | None:
        raw = headers.get("Set-Cookie") if headers else None
        if not raw:
            return None
        jar = http.cookies.SimpleCookie()
        jar.load(raw)
        return f"session={jar['session'].value}" if "session" in jar else None

    def register(self, username="salah", password="a-long-passphrase-99"):
        _, headers, _ = self.post(
            "/register",
            f"username={username}&password={password}&confirm={password}")
        return self.session_of(headers)

    def csrf_token(self, cookie: str) -> str:
        _, _, body = self.get("/", cookie)
        match = re.search(r'name="csrf_token" value="([^"]+)"', body)
        self.assertIsNotNone(match, "no CSRF token rendered on the notes page")
        return match.group(1)


class TestSecurityHeaders(LiveServerTestCase):
    def test_csp_is_sent(self):
        _, headers, _ = self.get("/login")
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])

    def test_clickjacking_and_sniffing_headers_are_sent(self):
        _, headers, _ = self.get("/login")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")

    def test_responses_are_not_cached(self):
        _, headers, _ = self.get("/login")
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_python_version_is_not_advertised(self):
        _, headers, _ = self.get("/login")
        self.assertNotIn("Python", headers.get("Server", ""))


class TestCookieFlags(LiveServerTestCase):
    def test_session_cookie_is_httponly_and_samesite(self):
        """HttpOnly blocks theft via XSS; SameSite blocks CSRF."""
        _, headers, _ = self.post(
            "/register",
            "username=salah&password=a-long-passphrase-99"
            "&confirm=a-long-passphrase-99")
        raw = headers.get("Set-Cookie")
        self.assertIn("HttpOnly", raw)
        self.assertIn("SameSite=Strict", raw)

    def test_secure_flag_follows_the_setting(self):
        _, headers, _ = self.post(
            "/register",
            "username=salah&password=a-long-passphrase-99"
            "&confirm=a-long-passphrase-99")
        # This server was started with secure_cookies=False.
        self.assertNotIn("Secure", headers.get("Set-Cookie"))


class TestAuthenticationFlow(LiveServerTestCase):
    def test_registration_creates_a_session(self):
        self.assertIsNotNone(self.register())

    def test_anonymous_request_is_redirected_to_login(self):
        status, headers, _ = self.post("/notes/new", "title=a&body=b")
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/login")

    def test_wrong_password_is_rejected(self):
        self.register()
        status, _, body = self.post(
            "/login", "username=salah&password=wrong-password")
        self.assertEqual(status, 401)
        self.assertIn("Invalid username or password", body)

    def test_unknown_user_gets_the_same_message_as_wrong_password(self):
        """User enumeration: the two failures must be indistinguishable."""
        self.register()
        _, _, wrong_pw = self.post(
            "/login", "username=salah&password=wrong-password")
        _, _, no_user = self.post(
            "/login", "username=ghost&password=wrong-password")
        self.assertIn("Invalid username or password", wrong_pw)
        self.assertIn("Invalid username or password", no_user)

    def test_correct_password_logs_in(self):
        self.register()
        status, headers, _ = self.post(
            "/login", "username=salah&password=a-long-passphrase-99")
        self.assertEqual(status, 303)
        self.assertIsNotNone(self.session_of(headers))

    def test_account_locks_after_repeated_failures(self):
        self.register()
        for _ in range(securenotes.MAX_FAILED_LOGINS):
            self.post("/login", "username=salah&password=wrong-password")
        status, _, body = self.post(
            "/login", "username=salah&password=wrong-password")
        self.assertEqual(status, 429)
        self.assertIn("locked", body)

    def test_logout_expires_the_cookie(self):
        cookie = self.register()
        _, headers, _ = self.get("/logout", cookie)
        self.assertIn("Max-Age=0", headers.get("Set-Cookie", ""))

    def test_duplicate_registration_is_refused_vaguely(self):
        self.register()
        status, _, body = self.post(
            "/register",
            "username=salah&password=a-long-passphrase-99"
            "&confirm=a-long-passphrase-99")
        self.assertEqual(status, 409)
        self.assertIn("not available", body)


class TestCsrfProtection(LiveServerTestCase):
    def test_missing_token_is_rejected(self):
        cookie = self.register()
        status, _, _ = self.post("/notes/new", "title=a&body=b", cookie)
        self.assertEqual(status, 403)

    def test_wrong_token_is_rejected(self):
        cookie = self.register()
        status, _, _ = self.post(
            "/notes/new", "csrf_token=forged&title=a&body=b", cookie)
        self.assertEqual(status, 403)

    def test_correct_token_is_accepted(self):
        cookie = self.register()
        token = self.csrf_token(cookie)
        status, _, _ = self.post(
            "/notes/new", f"csrf_token={token}&title=a&body=b", cookie)
        self.assertEqual(status, 303)

    def test_another_users_token_is_rejected(self):
        """Tokens are per session, not global."""
        victim = self.register("victim")
        attacker = self.register("attacker", "another-long-passphrase-1")
        stolen = self.csrf_token(attacker)
        status, _, _ = self.post(
            "/notes/new", f"csrf_token={stolen}&title=a&body=b", victim)
        self.assertEqual(status, 403)


class TestXssEscaping(LiveServerTestCase):
    def add_note(self, cookie: str, title: str, body: str):
        token = self.csrf_token(cookie)
        return self.post("/notes/new",
                         f"csrf_token={token}&title={title}&body={body}", cookie)

    def test_script_payload_in_a_title_is_escaped(self):
        cookie = self.register()
        self.add_note(cookie, "%3Cscript%3Ealert(1)%3C/script%3E", "safe")
        _, _, body = self.get("/", cookie)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn("&lt;script&gt;", body)

    def test_image_onerror_payload_in_a_body_is_escaped(self):
        cookie = self.register()
        self.add_note(cookie, "t", "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E")
        _, _, body = self.get("/", cookie)
        self.assertNotIn("<img src=x onerror=alert(1)>", body)


class TestStaticFiles(LiveServerTestCase):
    def test_stylesheet_is_served(self):
        status, headers, _ = self.get("/static/style.css")
        self.assertEqual(status, 200)
        self.assertIn("text/css", headers["Content-Type"])

    def test_path_traversal_is_blocked(self):
        status, _, _ = self.get("/static/../securenotes.py")
        self.assertEqual(status, 404)

    def test_unknown_page_is_404(self):
        status, _, _ = self.get("/no-such-page")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
