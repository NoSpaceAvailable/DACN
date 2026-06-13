import hashlib
import sqlite3
from fastapi import HTTPException, Header
import secrets, jwt
import os
import json
from datetime import datetime
from db import DB_FILE

SECRET_KEY = secrets.token_hex(128)
ALGORITHM = "HS256"

def verify_token(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = authorization.split("Bearer ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("username")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute("SELECT username FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")

def get_user_by(field: str, value: str):
    with sqlite3.connect(DB_FILE) as conn:
        query = f"SELECT username, email, dob, password_hash FROM users WHERE {field} = ?"
        rows = conn.execute(query, (value,)).fetchall()

    if not rows:
        return None
    return {"username": rows[0][0], "email": rows[0][1], "dob": rows[0][2], "password_hash": rows[0][3]}

def hash_sha256(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def filter(file_name: str):
    if ".." in file_name or file_name.startswith("/"):
        raise HTTPException(status_code=403, detail="Forbidden character(s)")

def log_request(session_id: str, endpoint: str, response_data):
    log_dir = "/home/appuser/logs"
    
    os.makedirs(log_dir, mode=0o755, exist_ok=True)
    
    log_file = os.path.join(log_dir, f"{session_id}.log")
    
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "endpoint": endpoint,
        "response": response_data
    }
    
    try:
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[ERROR] Failed to log request: {e}")