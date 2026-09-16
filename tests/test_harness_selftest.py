"""Self-test for the shared fakes. Copied into each repo alongside fakes.py."""
from __future__ import annotations

import socket
import threading
import unittest
import urllib.error
import urllib.request

from tests.support.fakes import closed_port, http_fake, tcp_listener


class TestTcpListener(unittest.TestCase):
    def test_accepts_a_connection(self):
        with tcp_listener() as (host, port):
            with socket.create_connection((host, port), timeout=2) as sock:
                self.assertEqual(sock.getpeername()[1], port)

    def test_serves_a_banner(self):
        with tcp_listener(banner=b"SSH-2.0-OpenSSH_9.6\r\n") as (host, port):
            with socket.create_connection((host, port), timeout=2) as sock:
                sock.settimeout(2)
                self.assertIn(b"OpenSSH", sock.recv(64))

    def test_port_is_ephemeral_and_free(self):
        with tcp_listener() as (_, first):
            with tcp_listener() as (_, second):
                self.assertNotEqual(first, second)

    def test_shuts_down_without_leaking_threads(self):
        before = threading.active_count()
        with tcp_listener() as (host, port):
            socket.create_connection((host, port), timeout=2).close()
        self.assertLessEqual(threading.active_count(), before)

    def test_closed_port_refuses(self):
        host, port = closed_port()
        with self.assertRaises(OSError):
            socket.create_connection((host, port), timeout=2)


class TestHttpFake(unittest.TestCase):
    def test_serves_programmed_body_and_status(self):
        routes = {"/hello": (200, {"X-Test": "yes"}, "world")}
        with http_fake(routes) as (base, _):
            with urllib.request.urlopen(base + "/hello", timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.headers["X-Test"], "yes")
                self.assertEqual(resp.read().decode(), "world")

    def test_unmatched_path_returns_default(self):
        with http_fake({}) as (base, _):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(base + "/missing", timeout=5)
            ctx.exception.close()
            self.assertEqual(ctx.exception.code, 404)

    def test_custom_default_response(self):
        with http_fake({}, default=(500, {}, "boom")) as (base, _):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(base + "/anything", timeout=5)
            ctx.exception.close()
            self.assertEqual(ctx.exception.code, 500)

    def test_sequenced_responses_advance_then_hold(self):
        routes = {"/seq": [(200, {}, "first"), (429, {}, "slow down")]}
        with http_fake(routes) as (base, _):
            with urllib.request.urlopen(base + "/seq", timeout=5) as resp:
                self.assertEqual(resp.read().decode(), "first")
            for _ in range(2):
                with self.assertRaises(urllib.error.HTTPError) as ctx:
                    urllib.request.urlopen(base + "/seq", timeout=5)
                ctx.exception.close()
                self.assertEqual(ctx.exception.code, 429)

    def test_recorder_captures_requests(self):
        with http_fake({"/a": (200, {}, "ok")}) as (base, recorder):
            urllib.request.urlopen(base + "/a", timeout=5).close()
            urllib.request.urlopen(base + "/a", timeout=5).close()
            self.assertEqual(recorder.count("/a"), 2)
            self.assertIn("/a", recorder.paths)
            self.assertEqual(recorder.requests[0]["method"], "GET")

    def test_recorder_captures_headers(self):
        with http_fake({"/h": (200, {}, "ok")}) as (base, recorder):
            req = urllib.request.Request(base + "/h",
                                         headers={"User-Agent": "probe/1.0"})
            urllib.request.urlopen(req, timeout=5).close()
            self.assertEqual(recorder.requests[0]["headers"]["user-agent"],
                             "probe/1.0")

    def test_head_request_sends_no_body(self):
        with http_fake({"/h": (200, {}, "hidden")}) as (base, _):
            req = urllib.request.Request(base + "/h", method="HEAD")
            with urllib.request.urlopen(req, timeout=5) as resp:
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.read(), b"")


if __name__ == "__main__":
    unittest.main()
