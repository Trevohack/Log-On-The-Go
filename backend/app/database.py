import sqlite3
import hashlib
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "users.db"

def init_db():
    """Initialize the database and create users table"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def add_user(username: str, password: str):
    """Add a new user to the database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        password_hash = hash_password(password)
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        conn.commit()
        print(f"User '{username}' added successfully")
    except sqlite3.IntegrityError:
        print(f"User '{username}' already exists")
    finally:
        conn.close()

def verify_user(username: str, password: str) -> bool:
    """Verify user credentials"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    password_hash = hash_password(password)
    cursor.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,)
    )
    
    result = cursor.fetchone()
    conn.close()
    
    if result and result[0] == password_hash:
        return True
    return False
