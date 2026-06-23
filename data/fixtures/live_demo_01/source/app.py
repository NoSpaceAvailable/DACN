"""Minimal notes server (intentionally vulnerable) — live-exploit demo target.

Bug: /read?path=<...> opens any path with no sanitisation -> arbitrary file
read (LFI / path traversal). The flag lives at /flag.txt inside the container.
"""
import http.server
import socketserver
import urllib.parse

PORT = 8080


class Handler(http.server.BaseHTTPRequestHandler):
    def _send(self, body: bytes, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/read":
            q = urllib.parse.parse_qs(u.query)
            path = q.get("path", [""])[0]
            # BUG: user-controlled path passed straight to open() — no allowlist,
            # no normalisation. Arbitrary file read.
            try:
                with open(path, "r", errors="ignore") as f:
                    self._send(f.read().encode())
            except Exception as exc:
                self._send(f"error: {exc}".encode(), status=404)
        else:
            self._send(b"Notes service. Try /read?path=notes.txt")

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
        httpd.serve_forever()
