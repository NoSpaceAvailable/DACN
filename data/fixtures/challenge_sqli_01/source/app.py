import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

def check_login(username: str, password: str) -> bool:
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    # BUG: unsafe string formatting with attacker-controlled input.
    query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"
    row = cur.execute(query).fetchone()
    return row is not None

@app.post("/login")
def login():
    ok = check_login(request.form["username"], request.form["password"])
    return jsonify({"ok": ok})
