import sqlite3
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

BLOCKED_TOKENS = (
    "union", "select", "--", "/*", "*/",
    "or 1=1", "or true", "drop ", "insert ", ";",
)


def has_forbidden_token(s: str) -> bool:
    low = s.lower()
    return any(tok in low for tok in BLOCKED_TOKENS)


def check_login(username: str, password: str) -> bool:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT)")
    cur.execute("INSERT INTO users VALUES (1, 'admin', 's3cr3t')")
    query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"
    row = cur.execute(query).fetchone()
    return row is not None


@app.post("/login")
def login():
    username = request.form["username"]
    password = request.form["password"]
    if has_forbidden_token(username):
        abort(400, "WAF: forbidden token in username")
    ok = check_login(username, password)
    return jsonify({"ok": ok})
