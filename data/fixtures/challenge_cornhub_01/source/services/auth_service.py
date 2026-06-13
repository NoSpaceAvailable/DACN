import sqlite3
import datetime
import jwt
from fastapi import HTTPException
from db import DB_FILE
from utils import get_user_by, hash_sha256, SECRET_KEY, ALGORITHM

def login(username: str, password: str):
    user = get_user_by("username", username)
    if not user or hash_sha256(password) != user["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    payload = {
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"message": f"Welcome {username}", "access_token": token}

def update_password(username: str, token: str, new_password: str):
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute("SELECT token, expires_at FROM reset_tokens WHERE username=?", (username,)).fetchone()

    if not row:
        raise HTTPException(status_code=400, detail="No reset request found")

    stored_token, expires_at = row
    if stored_token != token:
        raise HTTPException(status_code=400, detail="Invalid token")

    if datetime.datetime.now() > datetime.datetime.fromisoformat(expires_at):
        raise HTTPException(status_code=400, detail="Token expired")

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("UPDATE users SET password_hash=? WHERE username=?", 
                     (hash_sha256(new_password), username))
        conn.execute("DELETE FROM reset_tokens WHERE username=?", (username,))

    return {"message": f"Password updated successfully for {username}"}

def forgot_password(email: str):
    user = get_user_by("email", email)
    if not user:
        raise HTTPException(status_code=404, detail="Email not found")

    timestamp = datetime.datetime.now().strftime("%Y:%m:%d-%H:%M")
    base = f"{user['email']}{user['username']}{user['dob']}{timestamp}"
    token = hash_sha256(base)
    expiry = (datetime.datetime.now() + datetime.timedelta(minutes=15)).isoformat()

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT OR REPLACE INTO reset_tokens (username, token, expires_at) VALUES (?, ?, ?)", 
                     (user["username"], token, expiry))

    print(f"[DEBUG] Forgot password requested for {base}")
    print(f"[DEBUG] Reset token for {email}: {token}")
    print(f"[DEBUG] Token expires at: {expiry}")

    return {"message": "Reset token generated", "token": token}