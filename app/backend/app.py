"""
UserManager API — v1.2.4
Internal user management service. Do not expose to public internet.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import jwt
import datetime
import os

app = Flask(__name__)
CORS(app)

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-2024")
DB_PATH = os.path.join(os.path.dirname(__file__), "lab.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# AUTH
# ---------------------------------------------------------------------------

@app.route("/api/login", methods=["POST"])
def login():
    """Authenticate user and return JWT token."""
    data = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")

    db = get_db()

    # VULNERABILITY 1 — SQL Injection (CWE-89)
    # Dynamic query built with string concatenation; no parameterized query used.
    query = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND password = '"
        + password
        + "'"
    )
    user = db.execute(query).fetchone()

    if user:
        token = jwt.encode(
            {
                "user_id": user["id"],
                "role": user["role"],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2),
            },
            SECRET_KEY,
            algorithm="HS256",
        )
        return jsonify({"token": token, "role": user["role"]})

    return jsonify({"error": "Invalid credentials"}), 401


# ---------------------------------------------------------------------------
# USERS
# ---------------------------------------------------------------------------

@app.route("/api/user", methods=["GET"])
def get_user():
    """Return user profile by ID."""
    # VULNERABILITY 2 — Missing input validation / type enforcement (CWE-20)
    # user_id is taken directly from query string with no int() cast,
    # no bounds check, and no parameterized binding — also injectable.
    user_id = request.args.get("id")

    db = get_db()
    user = db.execute(
        f"SELECT id, username, email FROM users WHERE id = {user_id}"
    ).fetchone()

    if user:
        return jsonify(dict(user))
    return jsonify({"error": "User not found"}), 404


@app.route("/api/profile", methods=["GET"])
def get_profile():
    """Return profile of the authenticated caller."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        db = get_db()
        user = db.execute(
            "SELECT id, username, email, role FROM users WHERE id = ?",
            (payload["user_id"],),
        ).fetchone()
        return jsonify(dict(user))
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401


# ---------------------------------------------------------------------------
# ADMIN
# ---------------------------------------------------------------------------

@app.route("/api/admin/users", methods=["GET"])
def list_all_users():
    """[Admin] List all registered users."""
    # VULNERABILITY 4 — Broken Access Control / Client-Side Only Enforcement (CWE-602)
    # No token verification, no role check. Any unauthenticated request succeeds.
    # The frontend hides this button for non-admins, but the endpoint itself is open.
    db = get_db()
    users = db.execute(
        "SELECT id, username, email, role FROM users"
    ).fetchall()
    return jsonify({"users": [dict(u) for u in users]})


@app.route("/api/admin/delete/<int:uid>", methods=["DELETE"])
def delete_user(uid):
    """[Admin] Delete a user by ID."""
    # Same issue: no auth check on a destructive endpoint.
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (uid,))
    db.commit()
    return jsonify({"message": f"User {uid} deleted"})


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
