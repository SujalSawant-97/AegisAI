"""
A tiny local HTTP application, built with the standard library only, used to
give scanners known-vulnerable and known-secure endpoints to test against.

This is NOT part of the shipped engine — it's a test fixture per the
"Testing Strategy" requirement: every vulnerability should have a known
vulnerable endpoint and a known secure endpoint, so we can assert both
"vulnerable application -> finding" and "secure application -> no finding".
"""

from __future__ import annotations

import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class TestAppHandler(BaseHTTPRequestHandler):
    __test__ = False  # Prevent pytest collection warning

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - silence default logging
        pass

    def _send(
        self,
        status: int,
        body: bytes = b"",
        extra_headers: dict[str, str] | None = None,
        content_type: str = "text/plain",
    ) -> None:
        self.send_response(status)
        headers = dict(extra_headers or {})
        if "Content-Type" not in headers:
            headers["Content-Type"] = content_type
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _read_body(self) -> str:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            return self.rfile.read(content_length).decode("utf-8", errors="replace")
        return ""

    def do_GET(self) -> None:  # noqa: N802 - required method name
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # 1. Security Headers
        if path == "/secure":
            self._send(
                200,
                b"secure ok",
                {
                    "Content-Security-Policy": "default-src 'self'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "strict-origin-when-cross-origin",
                },
            )
        elif path == "/vulnerable":
            self._send(200, b"vulnerable ok")

        # 2. CORS
        elif path == "/cors-secure":
            origin = self.headers.get("Origin", "")
            headers = {}
            if origin == "https://trusted.example":
                headers["Access-Control-Allow-Origin"] = origin
            self._send(200, b"cors secure ok", headers)
        elif path == "/cors-vulnerable":
            origin = self.headers.get("Origin", "*")
            self._send(
                200,
                b"cors vulnerable ok",
                {
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                },
            )

        # 3. Authentication
        elif path == "/auth/secure":
            auth = self.headers.get("Authorization", "")
            if auth == "Bearer valid-secret-token":
                self._send(200, b'{"user": "alice", "status": "authenticated"}', content_type="application/json")
            else:
                self._send(401, b"Unauthorized: Missing or invalid token", content_type="text/plain")

        elif path == "/auth/vulnerable":
            # Vulnerable: Accepts unauthenticated or invalid token requests
            self._send(200, b'{"user": "guest", "secret": "leaked-data"}', content_type="application/json")

        elif path == "/auth/disclosure":
            self._send(
                401,
                b"Traceback (most recent call last):\n  File 'auth.py', line 42\nNullPointerException: Auth failed",
                content_type="text/plain",
            )

        # 4. Authorization
        elif path == "/authz/admin-secure":
            auth = self.headers.get("Authorization", "")
            if auth == "Bearer admin-token":
                self._send(200, b'{"admin": "dashboard"}', content_type="application/json")
            elif auth == "Bearer user-token":
                self._send(403, b"Forbidden: Insufficient privileges", content_type="text/plain")
            else:
                self._send(401, b"Unauthorized", content_type="text/plain")

        elif path == "/authz/admin-vulnerable":
            # Broken Function Level Authorization: allows low-privilege user-token
            auth = self.headers.get("Authorization", "")
            if auth in ("Bearer user-token", "Bearer admin-token"):
                self._send(200, b'{"admin": "dashboard", "privileged_data": true}', content_type="application/json")
            else:
                self._send(401, b"Unauthorized", content_type="text/plain")

        elif path.startswith("/authz/user-secure/"):
            user_id = path.split("/")[-1]
            auth = self.headers.get("Authorization", "")
            # Only user 1 token can access user 1
            if auth == "Bearer user-1-token" and user_id == "1":
                self._send(200, b'{"id": 1, "profile": "Alice"}', content_type="application/json")
            elif auth == "Bearer user-1-token" and user_id != "1":
                self._send(403, b"Forbidden: Cannot access other users", content_type="text/plain")
            else:
                self._send(401, b"Unauthorized", content_type="text/plain")

        elif path.startswith("/authz/user-vulnerable/"):
            # Broken Object Level Authorization: allows user 1 token to access any user
            user_id = path.split("/")[-1]
            auth = self.headers.get("Authorization", "")
            if auth:
                self._send(200, f'{{"id": {user_id}, "profile": "User_{user_id}"}}'.encode(), content_type="application/json")
            else:
                self._send(401, b"Unauthorized", content_type="text/plain")

        # 5. SQL Injection
        elif path == "/sqli-secure":
            param_id = query.get("id", ["1"])[0]
            # Secure parameterized query simulation: safely handles quotes
            self._send(200, f'{{"id": "{html.escape(param_id)}", "name": "safe_item"}}'.encode(), content_type="application/json")

        elif path == "/sqli-error-vulnerable":
            param_id = query.get("id", ["1"])[0]
            if "'" in param_id or '"' in param_id:
                self._send(500, b"sqlite3.OperationalError: near syntax error in SELECT * FROM items WHERE id = " + param_id.encode())
            else:
                self._send(200, b'{"id": "1", "name": "widget"}', content_type="application/json")

        elif path == "/sqli-boolean-vulnerable":
            param_id = query.get("id", ["1"])[0]
            if "' OR '1'='1" in param_id or " OR 1=1" in param_id or param_id == "1":
                self._send(200, b'{"items": ["item1", "item2", "item3"]}', content_type="application/json")
            elif "' AND '1'='2" in param_id or " AND 1=2" in param_id:
                self._send(200, b'{"items": []}', content_type="application/json")
            else:
                self._send(404, b'{"error": "not found"}', content_type="application/json")

        # 6. XSS
        elif path == "/xss-secure":
            q = query.get("q", [""])[0]
            escaped_q = html.escape(q)
            body = f"<html><body><h1>Search Results</h1><p>{escaped_q}</p></body></html>".encode()
            self._send(200, body, content_type="text/html; charset=utf-8")

        elif path == "/xss-vulnerable":
            q = query.get("q", [""])[0]
            # Unescaped reflection in HTML
            body = f"<html><body><h1>Search Results</h1><p>{q}</p></body></html>".encode()
            self._send(200, body, content_type="text/html; charset=utf-8")

        elif path == "/xss-json-safe":
            q = query.get("q", [""])[0]
            body = json.dumps({"query": q, "status": "ok"}).encode()
            self._send(200, body, content_type="application/json")

        elif path == "/xss-csp-protected":
            q = query.get("q", [""])[0]
            body = f"<html><body><h1>Search</h1><p>{q}</p></body></html>".encode()
            self._send(
                200,
                body,
                extra_headers={"Content-Security-Policy": "default-src 'self'; script-src 'none'"},
                content_type="text/html",
            )

        else:
            self._send(404, b"not found")

    def do_POST(self) -> None:  # noqa: N802
        self.do_GET()

    def do_PUT(self) -> None:  # noqa: N802
        self.do_GET()

    def do_DELETE(self) -> None:  # noqa: N802
        self.do_GET()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.do_GET()


class TestApp:
    """Context-manager wrapper that runs the test app on a background thread."""

    __test__ = False  # Prevent pytest collection warning

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self._server = ThreadingHTTPServer((host, port), TestAppHandler)
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> "TestApp":
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self._server.shutdown()
        self._server.server_close()
