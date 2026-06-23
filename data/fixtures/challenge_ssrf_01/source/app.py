from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.post("/api/webhook/preview")
def preview():
    data = request.get_json(force=True) or {}
    url = data.get("url", "")
    # BUG: user-controlled url fetched server-side with no allowlist (SSRF)
    resp = requests.get(url, timeout=5)
    return jsonify({"status": resp.status_code, "snippet": resp.text[:200]})
