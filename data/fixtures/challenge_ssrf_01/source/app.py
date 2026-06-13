import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

@app.post("/api/webhook/preview")
def preview():
    url = request.json["url"]
    resp = requests.get(url, timeout=3)
    return jsonify({"status": resp.status_code, "size": len(resp.text), "title": resp.text[:40]})
