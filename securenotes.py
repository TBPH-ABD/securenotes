#!/usr/bin/env python3
"""securenotes — a small notes application built to demonstrate secure coding.

The feature set is deliberately tiny: register, log in, write notes. The point
is *how* it is built. Every control that a real application needs is present
and commented with the attack it stops:

  - PBKDF2-HMAC-SHA256 password hashing with a per-user salt
  - Session tokens stored as hashes, so a database leak yields no live sessions
  - Per-session CSRF tokens, compared in constant time
  - Login throttling and account lockout against credential brute forcing
  - Parameterised SQL everywhere (no string-built queries)
  - Contextual HTML escaping on every value rendered
  - Ownership checks on every object access (no IDOR)
  - A strict Content-Security-Policy and the full security header set

Standard library only: http.server, sqlite3, hashlib, secrets.
"""
from __future__ import annotations

import argparse
import html
import http.cookies
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# --- Security parameters ---------------------------------------------------
PBKDF2_ITERATIONS = 600_000   # OWASP guidance for PBKDF2-HMAC-SHA256
SALT_BYTES = 16
SESSION_BYTES = 32
SESSION_LIFETIME = timedelta(hours=8)
MAX_FAILED_LOGINS = 5
LOCKOUT_DURATION = timedelta(minutes=15)

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
MIN_PASSWORD_LENGTH = 12
MAX_TITLE = 120
MAX_BODY = 10_000

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


# ===========================================================================
# Data layer — every query is parameterised, so input can never become SQL.
# ===========================================================================
class Database:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._create_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _create_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    username        TEXT    NOT NULL UNIQUE,
                    password_hash   BLOB    NOT NULL,
                    salt            BLOB    NOT NULL,
                    iterations      INTEGER NOT NULL,
                    created_at      TEXT    NOT NULL,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until    TEXT
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash  TEXT PRIMARY KEY,
                    user_id     INTEGER NOT NULL,
                    csrf_token  TEXT    NOT NULL,
                    created_at  TEXT    NOT NULL,
                    expires_at  TEXT    NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS notes (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id    INTEGER NOT NULL,
                    title      TEXT    NOT NULL,
                    body       TEXT    NOT NULL,
                    created_at TEXT    NOT NULL,
                    updated_at TEXT    NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_notes_user ON notes(user_id);
            """)

    # --- users -------------------------------------------------------------
    def create_user(self, username: str, password: str) -> int | None:
        salt = secrets.token_bytes(SALT_BYTES)
        digest = hash_password(password, salt, PBKDF2_ITERATIONS)
        with self._lock, self._connect() as conn:
            try:
                cursor = conn.execute(
                    "INSERT INTO users (username, password_hash, salt,"
                    " iterations, created_at) VALUES (?, ?, ?, ?, ?)",
                    (username, digest, salt, PBKDF2_ITERATIONS, now_iso()))
                return cursor.lastrowid
            except sqlite3.IntegrityError:
                return None  # username already taken

    def get_user(self, username: str) -> sqlite3.Row | None:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    def register_failure(self, user_id: int, attempts: int) -> None:
        locked = (now() + LOCKOUT_DURATION).isoformat() \
            if attempts >= MAX_FAILED_LOGINS else None
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ?"
                " WHERE id = ?", (attempts, locked, user_id))

    def clear_failures(self, user_id: int) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL"
                " WHERE id = ?", (user_id,))

    # --- sessions ----------------------------------------------------------
    def create_session(self, user_id: int) -> tuple[str, str]:
        """Returns (session_token, csrf_token). Only the hash is stored."""
        token = secrets.token_urlsafe(SESSION_BYTES)
        csrf = secrets.token_urlsafe(32)
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO sessions (token_hash, user_id, csrf_token,"
                " created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (token_digest(token), user_id, csrf, now_iso(),
                 (now() + SESSION_LIFETIME).isoformat()))
        return token, csrf

    def get_session(self, token: str) -> sqlite3.Row | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT s.*, u.username FROM sessions s"
                " JOIN users u ON u.id = s.user_id"
                " WHERE s.token_hash = ?", (token_digest(token),)).fetchone()
        if row is None:
            return None
        if datetime.fromisoformat(row["expires_at"]) < now():
            self.destroy_session(token)
            return None
        return row

    def destroy_session(self, token: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?",
                         (token_digest(token),))

    def purge_expired_sessions(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now_iso(),))

    # --- notes -------------------------------------------------------------
    def list_notes(self, user_id: int) -> list[sqlite3.Row]:
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM notes WHERE user_id = ? ORDER BY updated_at DESC",
                (user_id,)).fetchall()

    def add_note(self, user_id: int, title: str, body: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO notes (user_id, title, body, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (user_id, title, body, now_iso(), now_iso()))

    def delete_note(self, note_id: int, user_id: int) -> bool:
        # The user_id in the WHERE clause is the authorisation check: a user
        # cannot delete another user's note by guessing its id (IDOR).
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM notes WHERE id = ? AND user_id = ?",
                (note_id, user_id))
            return cursor.rowcount > 0


# ===========================================================================
# Crypto helpers
# ===========================================================================
def hash_password(password: str, salt: bytes, iterations: int) -> bytes:
    import hashlib
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)


def token_digest(token: str) -> str:
    """Sessions are stored hashed, so a database read does not yield live tokens."""
    import hashlib
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def now() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return now().isoformat()


# ===========================================================================
# Validation
# ===========================================================================
def validate_registration(username: str, password: str, confirm: str) -> list[str]:
    errors = []
    if not USERNAME_PATTERN.fullmatch(username):
        errors.append("Username must be 3-32 characters: letters, digits, "
                      "dot, dash, or underscore.")
    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} "
                      f"characters. Length beats complexity.")
    if password != confirm:
        errors.append("Passwords do not match.")
    return errors


# ===========================================================================
# Views — every interpolated value passes through html.escape()
# ===========================================================================
def page(title: str, body: str, username: str | None = None) -> bytes:
    nav = ""
    if username:
        nav = (f'<span class="who">{html.escape(username)}</span>'
               f'<a class="link" href="/logout">Log out</a>')
    document = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)} — securenotes</title>
<link rel="stylesheet" href="/static/style.css">
</head><body>
<header class="bar"><a class="brand" href="/">securenotes</a><nav>{nav}</nav></header>
<main>{body}</main>
</body></html>"""
    return document.encode("utf-8")


def alert_block(messages: list[str], kind: str = "error") -> str:
    if not messages:
        return ""
    items = "".join(f"<li>{html.escape(m)}</li>" for m in messages)
    return f'<ul class="alert {kind}">{items}</ul>'


def login_view(errors: list[str], notice: str = "") -> bytes:
    body = f"""
<div class="card narrow">
  <h1>Log in</h1>
  {alert_block([notice], "notice") if notice else ""}
  {alert_block(errors)}
  <form method="post" action="/login">
    <label for="u">Username</label>
    <input id="u" name="username" autocomplete="username" required maxlength="32">
    <label for="p">Password</label>
    <input id="p" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Log in</button>
  </form>
  <p class="muted">No account? <a href="/register">Register</a></p>
</div>"""
    return page("Log in", body)


def register_view(errors: list[str]) -> bytes:
    body = f"""
<div class="card narrow">
  <h1>Create an account</h1>
  {alert_block(errors)}
  <form method="post" action="/register">
    <label for="u">Username</label>
    <input id="u" name="username" autocomplete="username" required maxlength="32">
    <label for="p">Password</label>
    <input id="p" name="password" type="password" autocomplete="new-password" required>
    <label for="c">Confirm password</label>
    <input id="c" name="confirm" type="password" autocomplete="new-password" required>
    <p class="muted">At least {MIN_PASSWORD_LENGTH} characters. A passphrase of
    several words is stronger than a short string of symbols.</p>
    <button type="submit">Create account</button>
  </form>
  <p class="muted">Already registered? <a href="/login">Log in</a></p>
</div>"""
    return page("Register", body)


def notes_view(username: str, notes: list[sqlite3.Row], csrf: str,
               errors: list[str]) -> bytes:
    if notes:
        cards = "".join(f"""
    <article class="note">
      <h3>{html.escape(n['title'])}</h3>
      <p>{html.escape(n['body'])}</p>
      <footer>
        <time>{html.escape(n['updated_at'][:16].replace('T', ' '))}</time>
        <form method="post" action="/notes/delete">
          <input type="hidden" name="csrf_token" value="{html.escape(csrf)}">
          <input type="hidden" name="note_id" value="{int(n['id'])}">
          <button class="danger" type="submit">Delete</button>
        </form>
      </footer>
    </article>""" for n in notes)
    else:
        cards = '<p class="muted empty">No notes yet. Write your first one above.</p>'

    body = f"""
<div class="card">
  <h1>Your notes</h1>
  {alert_block(errors)}
  <form method="post" action="/notes/new" class="compose">
    <input type="hidden" name="csrf_token" value="{html.escape(csrf)}">
    <label for="t">Title</label>
    <input id="t" name="title" required maxlength="{MAX_TITLE}">
    <label for="b">Note</label>
    <textarea id="b" name="body" rows="4" required maxlength="{MAX_BODY}"></textarea>
    <button type="submit">Save note</button>
  </form>
</div>
<section class="notes">{cards}</section>"""
    return page("Notes", body, username)


# ===========================================================================
# HTTP layer
# ===========================================================================
def make_handler(db: Database, secure_cookies: bool):

    class Handler(BaseHTTPRequestHandler):
        server_version = "securenotes"
        sys_version = ""  # do not advertise the Python version

        def log_message(self, fmt, *args):
            pass

        # --- response helpers ---------------------------------------------
        def _headers(self, status: int, content_type: str, length: int,
                     cookie: str | None = None, location: str | None = None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(length))
            # No inline script or style is used anywhere, so the policy can be
            # strict enough to neutralise injected markup outright.
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'self'; "
                             "form-action 'self'; base-uri 'none'; "
                             "frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            if secure_cookies:
                self.send_header("Strict-Transport-Security",
                                 "max-age=31536000; includeSubDomains")
            if cookie:
                self.send_header("Set-Cookie", cookie)
            if location:
                self.send_header("Location", location)
            self.end_headers()

        def _html(self, body: bytes, status: int = 200, cookie: str | None = None):
            self._headers(status, "text/html; charset=utf-8", len(body), cookie)
            self.wfile.write(body)

        def _redirect(self, location: str, cookie: str | None = None):
            self._headers(303, "text/plain; charset=utf-8", 0, cookie, location)

        def _session_cookie(self, token: str, expire: bool = False) -> str:
            cookie = http.cookies.SimpleCookie()
            cookie["session"] = "" if expire else token
            morsel = cookie["session"]
            morsel["path"] = "/"
            morsel["httponly"] = True        # unreadable from JavaScript
            morsel["samesite"] = "Strict"    # not sent on cross-site requests
            if secure_cookies:
                morsel["secure"] = True      # HTTPS only
            morsel["max-age"] = 0 if expire else int(SESSION_LIFETIME.total_seconds())
            return morsel.OutputString()

        # --- request helpers ----------------------------------------------
        def _form(self) -> dict[str, str]:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > 1_000_000:
                return {}
            raw = self.rfile.read(length).decode("utf-8", "replace")
            return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

        def _session(self):
            raw = self.headers.get("Cookie")
            if not raw:
                return None
            cookie = http.cookies.SimpleCookie()
            cookie.load(raw)
            if "session" not in cookie:
                return None
            return db.get_session(cookie["session"].value)

        def _csrf_ok(self, form: dict, session) -> bool:
            supplied = form.get("csrf_token", "")
            # Constant-time comparison: a timing side channel must not reveal
            # how much of a guessed token was correct.
            return bool(supplied) and secrets.compare_digest(
                supplied, session["csrf_token"])

        # --- routing -------------------------------------------------------
        def do_GET(self):
            path = urlparse(self.path).path
            session = self._session()

            if path.startswith("/static/"):
                return self._static(path[len("/static/"):])
            if path == "/":
                if not session:
                    return self._redirect("/login")
                notes = db.list_notes(session["user_id"])
                return self._html(notes_view(session["username"], notes,
                                             session["csrf_token"], []))
            if path == "/login":
                return self._redirect("/") if session else self._html(login_view([]))
            if path == "/register":
                return self._redirect("/") if session else self._html(register_view([]))
            if path == "/logout":
                if session:
                    raw = http.cookies.SimpleCookie()
                    raw.load(self.headers.get("Cookie", ""))
                    db.destroy_session(raw["session"].value)
                return self._redirect("/login", self._session_cookie("", expire=True))
            return self._html(page("Not found", "<div class='card narrow'>"
                                   "<h1>Not found</h1></div>"), 404)

        def do_POST(self):
            path = urlparse(self.path).path
            form = self._form()
            session = self._session()

            if path == "/register":
                return self._do_register(form)
            if path == "/login":
                return self._do_login(form)

            # Everything below requires an authenticated session AND a valid
            # CSRF token, checked before any state changes.
            if not session:
                return self._redirect("/login")
            if not self._csrf_ok(form, session):
                return self._html(page("Rejected", "<div class='card narrow'>"
                                       "<h1>Request rejected</h1><p class='muted'>"
                                       "Invalid CSRF token. Reload and try again."
                                       "</p></div>"), 403)

            if path == "/notes/new":
                return self._do_new_note(form, session)
            if path == "/notes/delete":
                return self._do_delete_note(form, session)
            return self._redirect("/")

        # --- actions -------------------------------------------------------
        def _do_register(self, form):
            username = form.get("username", "").strip()
            password = form.get("password", "")
            confirm = form.get("confirm", "")

            errors = validate_registration(username, password, confirm)
            if errors:
                return self._html(register_view(errors), 400)

            user_id = db.create_user(username, password)
            if user_id is None:
                # Deliberately vague: confirming which usernames exist helps
                # an attacker build a target list.
                return self._html(register_view(
                    ["That username is not available."]), 409)

            token, _ = db.create_session(user_id)
            return self._redirect("/", self._session_cookie(token))

        def _do_login(self, form):
            username = form.get("username", "").strip()
            password = form.get("password", "")
            user = db.get_user(username)

            # One generic message for every failure mode, so the response never
            # distinguishes "no such user" from "wrong password".
            generic = ["Invalid username or password."]

            if user is None:
                # Spend comparable time anyway, so response latency does not
                # reveal whether the account exists.
                hash_password(password, b"0" * SALT_BYTES, PBKDF2_ITERATIONS)
                return self._html(login_view(generic), 401)

            if user["locked_until"]:
                if datetime.fromisoformat(user["locked_until"]) > now():
                    return self._html(login_view(
                        ["Account temporarily locked after repeated failed "
                         "attempts. Try again later."]), 429)
                db.clear_failures(user["id"])

            candidate = hash_password(password, user["salt"], user["iterations"])
            if not secrets.compare_digest(candidate, user["password_hash"]):
                db.register_failure(user["id"], user["failed_attempts"] + 1)
                return self._html(login_view(generic), 401)

            db.clear_failures(user["id"])
            # A fresh session id on every login defeats session fixation.
            token, _ = db.create_session(user["id"])
            return self._redirect("/", self._session_cookie(token))

        def _do_new_note(self, form, session):
            title = form.get("title", "").strip()
            body = form.get("body", "").strip()
            errors = []
            if not title or len(title) > MAX_TITLE:
                errors.append(f"Title is required and must be at most "
                              f"{MAX_TITLE} characters.")
            if not body or len(body) > MAX_BODY:
                errors.append(f"Note body is required and must be at most "
                              f"{MAX_BODY} characters.")
            if errors:
                notes = db.list_notes(session["user_id"])
                return self._html(notes_view(session["username"], notes,
                                             session["csrf_token"], errors), 400)
            db.add_note(session["user_id"], title, body)
            return self._redirect("/")

        def _do_delete_note(self, form, session):
            try:
                note_id = int(form.get("note_id", ""))
            except ValueError:
                return self._redirect("/")
            db.delete_note(note_id, session["user_id"])
            return self._redirect("/")

        # --- static --------------------------------------------------------
        def _static(self, relative: str):
            full = os.path.realpath(os.path.join(STATIC_DIR, relative))
            if not full.startswith(os.path.realpath(STATIC_DIR) + os.sep) \
                    or not os.path.isfile(full):
                return self._html(page("Not found", "<div class='card narrow'>"
                                       "<h1>Not found</h1></div>"), 404)
            with open(full, "rb") as fh:
                data = fh.read()
            self._headers(200, "text/css; charset=utf-8", len(data))
            self.wfile.write(data)

    return Handler


def session_reaper(db: Database) -> None:
    while True:
        time.sleep(600)
        db.purge_expired_sessions()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="A notes application built to demonstrate secure coding.")
    parser.add_argument("-d", "--database", default="securenotes.db",
                        help="SQLite database path (default securenotes.db)")
    parser.add_argument("--port", type=int, default=8000, help="port (default 8000)")
    parser.add_argument("--bind", default="127.0.0.1",
                        help="bind address (default 127.0.0.1)")
    parser.add_argument("--secure-cookies", action="store_true",
                        help="set Secure on cookies and send HSTS "
                             "(enable when served over HTTPS)")
    args = parser.parse_args(argv)

    db = Database(args.database)
    db.purge_expired_sessions()
    threading.Thread(target=session_reaper, args=(db,), daemon=True).start()

    server = ThreadingHTTPServer((args.bind, args.port),
                                 make_handler(db, args.secure_cookies))
    print(f"\n  securenotes on http://{args.bind}:{args.port}")
    print(f"  Database: {args.database}")
    if not args.secure_cookies:
        print("  Note: running without --secure-cookies (plain HTTP). "
              "Enable it behind TLS.")
    print("  Press Ctrl+C to stop.\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Shutting down...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
