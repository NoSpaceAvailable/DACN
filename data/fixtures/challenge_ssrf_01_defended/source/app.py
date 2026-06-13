import requests
from urllib.parse import urlparse
from flask import Flask, jsonify, request, abort

app = Flask(__name__)

BLOCKED_PREFIXES = (
    "127.",
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "169.254.",
    "0.0.0.0",
    "localhost",
)


def is_blocked(hostname: str) -> bool:
    if hostname is None:
        return True
    h = hostname.lower()
    return any(h.startswith(p) for p in BLOCKED_PREFIXES)


@app.post("/api/webhook/preview")
def preview():
    url = request.json["url"]
    parsed = urlparse(url)
    if is_blocked(parsed.hostname):
        abort(400, "blocked: internal host")
    resp = requests.get(url, timeout=3)
    return jsonify({"status": resp.status_code, "size": len(resp.text), "title": resp.text[:40]})
