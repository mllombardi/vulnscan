"""
Vulnerable example: SQL Injection + Hardcoded Credentials
OWASP: A03 Injection, A07 Identification and Authentication Failures
"""

import sqlite3
import logging

# VULN: Hardcoded database credentials
DB_HOST = "prod-db.internal"
DB_USER = "admin"
DB_PASSWORD = "SuperSecret123!"
DB_NAME = "users"

log = logging.getLogger(__name__)


def get_db():
    # Using a local SQLite file for demo purposes
    return sqlite3.connect("app.db")


def get_user_by_username(username: str) -> dict | None:
    """Fetch a user record by username."""
    conn = get_db()
    cursor = conn.cursor()

    # VULN: SQL Injection — user input concatenated directly into query
    query = "SELECT id, username, email, role FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()

    if row:
        return {"id": row[0], "username": row[1], "email": row[2], "role": row[3]}
    return None


def search_users(search_term: str) -> list[dict]:
    """Search users by name or email."""
    conn = get_db()
    cursor = conn.cursor()

    # VULN: SQL Injection via f-string
    query = f"SELECT id, username, email FROM users WHERE username LIKE '%{search_term}%' OR email LIKE '%{search_term}%'"
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()

    return [{"id": r[0], "username": r[1], "email": r[2]} for r in rows]


def delete_user(user_id: str) -> bool:
    """Delete a user by ID."""
    conn = get_db()
    cursor = conn.cursor()

    # VULN: SQL Injection — no parameterized query, ID treated as string
    cursor.execute("DELETE FROM users WHERE id = " + user_id)
    conn.commit()
    conn.close()
    return True


def log_login_attempt(username: str, success: bool) -> None:
    # VULN: Sensitive Data Exposure — logging raw username (PII) at INFO level
    log.info("Login attempt: username=%s success=%s", username, success)
