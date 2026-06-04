"""Seed the SQLite database for the lab."""
import sqlite3, os

DB_PATH = os.path.join(os.path.dirname(__file__), "lab.db")

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.executescript("""
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT    NOT NULL UNIQUE,
    password TEXT    NOT NULL,
    email    TEXT    NOT NULL,
    role     TEXT    NOT NULL DEFAULT 'user'
);

DELETE FROM users;

INSERT INTO users (username, password, email, role) VALUES
    ('alice',  'alice123',  'alice@lab.local',  'admin'),
    ('bob',    'bob456',    'bob@lab.local',    'user'),
    ('carol',  'carol789',  'carol@lab.local',  'user');
""")

conn.commit()
conn.close()
print("Database initialised at", DB_PATH)
