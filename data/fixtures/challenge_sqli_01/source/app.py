from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.post("/login")
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = sqlite3.connect("app.db")
    # BUG: unsafe SQL string formatting -> SQL injection / auth bypass
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    row = conn.execute(query).fetchone()
    return jsonify({"ok": bool(row)})
