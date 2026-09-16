"""Local test doubles for network-facing code.

Both helpers bind to 127.0.0.1 on an ephemeral port and yield a real address,
so the code under test exercises its genuine socket and HTTP paths without ever
contacting an external service.

Standard library only. This file is copied verbatim into each repository so
every repo stays standalone.
"""
from __future__ import annotations

import contextlib
import io
import socket
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def capture_cli(main, argv: list[str]) -> tuple[int, str]:
    """Run a tool's main() with output captured.

    Returns (exit_code, combined stdout+stderr) so tests can assert on the exit
    code and on what the user was told, without the text reaching the test log.
    """
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
        code = main(argv)
    return code, buffer.getvalue()


@contextmanager
def tcp_listener(banner: bytes | None = None, backlog: int = 8):
    """A real listening TCP socket on an ephemeral port.

    Yields (host, port). If `banner` is given, it is sent to each client on
    connect, which is what lets banner-grabbing code be tested for real.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(backlog)
    host, port = server.getsockname()
    stop = threading.Event()

    def serve() -> None:
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                if banner:
                    try:
                        conn.sendall(banner)
                    except OSError:
                        pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield host, port
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()


def closed_port() -> tuple[str, int]:
    """An address that is guaranteed to refuse connections.

    Binding and immediately closing reserves a port number that nothing is
    listening on, which is more reliable than guessing an unused port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        host, port = probe.getsockname()
    return host, port


class _Recorder:
    """Collects the requests a fake server received, for assertions."""

    def __init__(self) -> None:
        self.requests: list[dict] = []

    def add(self, method: str, path: str, headers: dict) -> None:
        self.requests.append({"method": method, "path": path,
                              "headers": headers})

    @property
    def paths(self) -> list[str]:
        return [r["path"] for r in self.requests]

    def count(self, path: str) -> int:
        return sum(1 for r in self.requests if r["path"] == path)


@contextmanager
def http_fake(routes: dict | None = None, default: tuple | None = None):
    """A real HTTP server serving programmed responses on an ephemeral port.

    `routes` maps a path to `(status, headers, body)`. A route value may also be
    a list of such tuples, which are returned in order on successive requests —
    that is how rate-limiting and redirect behaviour get tested.

    `default` is the response for any unmatched path; it defaults to a 404.

    Yields (base_url, recorder). `recorder.requests` holds what the server saw.
    """
    routes = dict(routes or {})
    default = default or (404, {}, "not found")
    recorder = _Recorder()
    sequences: dict[str, int] = {}

    class Handler(BaseHTTPRequestHandler):
        # HTTP/1.0 closes each connection immediately. Keep-alive would leave
        # handler threads parked waiting for a follow-up request, adding about
        # half a second to every test's teardown.
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):  # keep test output clean
            pass

        def _resolve(self, path: str):
            entry = routes.get(path, default)
            if isinstance(entry, list):
                index = sequences.get(path, 0)
                sequences[path] = index + 1
                entry = entry[min(index, len(entry) - 1)]
            return entry

        def _respond(self, body_allowed: bool = True):
            recorder.add(self.command, self.path,
                         {k.lower(): v for k, v in self.headers.items()})
            status, headers, body = self._resolve(self.path)
            payload = body.encode() if isinstance(body, str) else (body or b"")
            self.send_response(status)
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if body_allowed and payload:
                self.wfile.write(payload)

        def do_GET(self):
            self._respond()

        def do_HEAD(self):
            self._respond(body_allowed=False)

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            self._respond()

        def do_OPTIONS(self):
            self._respond()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    host, port = server.server_address[0], server.server_address[1]
    # serve_forever polls every 0.5s by default, and shutdown() waits for the
    # loop to notice — which would add half a second to every single test.
    thread = threading.Thread(target=server.serve_forever, args=(0.01,),
                              daemon=True)
    thread.start()
    try:
        yield f"http://{host}:{port}", recorder
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
