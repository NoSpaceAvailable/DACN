from flask import Flask, jsonify, request
import requests

app = Flask(__name__)
HISTORY = []


@app.post("/api/preview")
def preview():
    data = request.get_json(force=True) or {}
    url = data.get("url", "")
    # BUG: the user-supplied URL is fetched server-side with no allowlist,
    # scheme restriction, or block on link-local / internal addresses.
    # An attacker can reach http://169.254.169.254/ (cloud metadata),
    # internal services, and file:// style targets via SSRF.
    resp = requests.get(url, timeout=5)
    snippet = resp.text[:200]
    HISTORY.append(url)
    return jsonify({"url": url, "status": resp.status_code, "snippet": snippet})


@app.get("/api/preview/history")
def history():
    return jsonify({"history": HISTORY})
