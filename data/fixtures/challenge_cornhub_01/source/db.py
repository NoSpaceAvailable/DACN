import sqlite3
import os
import hashlib
import secrets

DB_FILE = "./data/app.db"

def init_db():
    if not os.path.exists(DB_FILE):
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                dob TEXT,
                password_hash TEXT
            )
            """)
            conn.execute("""
            CREATE TABLE IF NOT EXISTS reset_tokens (
                username TEXT PRIMARY KEY,
                token TEXT,
                expires_at TEXT
            )
            """)
            cur = conn.execute("SELECT COUNT(*) FROM users WHERE username='admin'")
            if cur.fetchone()[0] == 0:
                plain_pw = secrets.token_hex(64)
                hashed_pw = hashlib.sha256(plain_pw.encode()).hexdigest()
                conn.execute("INSERT INTO users (username, email, dob, password_hash) VALUES (?, ?, ?, ?)", 
                             ("admin", "admin@cornhub.com", "2005-08-05", hashed_pw))
                print(f"[INIT] Admin created -> username='admin', password='{plain_pw}'")
