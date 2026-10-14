#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web lab CO Y DINH SSRF - chi dung de demo/kiem thu ssrf_scanner trong may ca nhan.
KHONG deploy ra Internet.

Chay:  python lab/vulnerable_app.py            # KHONG loc
       python lab/vulnerable_app.py --filter   # bat blacklist (de test bypass)

Endpoint:
  GET  /                -> trang chu (hien che do)
  GET  /fetch?url=...   -> SSRF (GET), co the bi filter chan
  POST /fetch  body:url=...  -> SSRF qua body POST (test --data)
  POST /login  body:username=&password=  -> set cookie 'sess' neu dung
                                             (user demo: admin / admin123)
  GET  /secure-fetch?url=...  -> SSRF NHUNG yeu cau cookie 'sess' (sau dang nhap)
  GET  /latest/meta-data      -> gia lap trang metadata noi bo
"""
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import urllib.request

PORT = 5000
USE_FILTER = "--filter" in sys.argv
BLACKLIST = ["127.0.0.1", "localhost", "169.254.169.254", "0.0.0.0", "metadata"]
VALID_USER, VALID_PASS = "admin", "admin123"
SESSION_COOKIE = "sess=secret-session-123"

FAKE_METADATA = b'{"instance-id":"i-123","ami-id":"ami-0abcd","iam":{"role":"admin"},"meta-data":"SECRET"}'


def blocked(url: str) -> bool:
    if not USE_FILTER:
        return False
    low = url.lower()
    return any(bad in low for bad in BLACKLIST)


def do_ssrf(url):
    """Tai URL (day la cho dinh loi SSRF co y)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ssrf-lab"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return 200, r.read()[:5000]
    except Exception as e:
        return 502, f"loi khi fetch: {e}".encode()


class Handler(BaseHTTPRequestHandler):
    def _body_params(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        return parse_qs(self.rfile.read(n).decode("utf-8", "replace")) if n else {}

    def _has_session(self):
        return SESSION_COOKIE in (self.headers.get("Cookie", "") or "")

    def do_GET(self):
        parts = urlparse(self.path)
        qs = parse_qs(parts.query)

        if parts.path.startswith("/latest/meta-data"):
            return self._send(200, FAKE_METADATA)
        if parts.path == "/":
            mode = "CO LOC (blacklist)" if USE_FILTER else "KHONG LOC"
            return self._send(200, f"<h1>SSRF Lab</h1><p>Che do: {mode}</p>".encode())

        if parts.path == "/fetch":
            url = (qs.get("url") or qs.get("uri") or [""])[0]
            if not url:
                return self._send(400, b"thieu tham so url")
            if blocked(url):
                return self._send(403, b"BLOCKED: dia chi noi bo bi cam")
            return self._send(*do_ssrf(url))

        if parts.path == "/secure-fetch":
            if not self._has_session():
                return self._send(401, b"UNAUTHORIZED: can dang nhap (thieu cookie sess)")
            url = (qs.get("url") or [""])[0]
            if not url:
                return self._send(400, b"thieu tham so url")
            if blocked(url):
                return self._send(403, b"BLOCKED: dia chi noi bo bi cam")
            return self._send(*do_ssrf(url))

        return self._send(404, b"not found")

    def do_POST(self):
        parts = urlparse(self.path)
        form = self._body_params()

        if parts.path == "/login":
            u = (form.get("username") or [""])[0]
            p = (form.get("password") or [""])[0]
            if u == VALID_USER and p == VALID_PASS:
                self.send_response(200)
                self.send_header("Set-Cookie", SESSION_COOKIE + "; Path=/")
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                return self.wfile.write(b"login ok")
            return self._send(403, b"sai username/password")

        if parts.path == "/fetch":
            url = (form.get("url") or form.get("uri") or [""])[0]
            if not url:
                return self._send(400, b"thieu tham so url")
            if blocked(url):
                return self._send(403, b"BLOCKED: dia chi noi bo bi cam")
            return self._send(*do_ssrf(url))

        return self._send(404, b"not found")

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    mode = "CO LOC (--filter)" if USE_FILTER else "KHONG LOC"
    print(f"[SSRF LAB] http://127.0.0.1:{PORT}  | che do: {mode}")
    print(f"           user demo: {VALID_USER}/{VALID_PASS}  (POST /login)  (Ctrl+C de dung)")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
