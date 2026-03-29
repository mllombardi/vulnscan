"""
Vulnerable example: Broken Authentication + Sensitive Data Exposure
OWASP: A07 Identification and Authentication Failures, A02 Cryptographic Failures
"""

import hashlib
import random
import time
from flask import Flask, request, session

app = Flask(__name__)

# VULN: Hardcoded weak secret key — easy to brute-force session tokens
app.secret_key = "secret"

# VULN: Hardcoded admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"


def hash_password(password: str) -> str:
    # VULN: MD5 is cryptographically broken and unsuitable for password hashing
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(stored_hash: str, provided_password: str) -> bool:
    # VULN: MD5 — no salt, vulnerable to rainbow table attacks
    return stored_hash == hashlib.md5(provided_password.encode()).hexdigest()


def generate_reset_token(user_id: int) -> str:
    # VULN: Using random (not cryptographically secure) for security token
    random.seed(time.time())
    token = str(random.randint(100000, 999999))
    return token


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    # VULN: No rate limiting — unlimited brute-force attempts allowed
    # VULN: Timing attack — comparison short-circuits on first mismatch
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session["user"] = username
        session["role"] = "admin"
        return {"status": "ok"}

    # VULN: Verbose error reveals whether username exists
    from db_utils import get_user_by_username
    user = get_user_by_username(username)
    if not user:
        return {"error": f"No account found for username '{username}'"}, 401

    return {"error": "Incorrect password"}, 401


@app.route("/profile")
def profile():
    # VULN: No authentication check — any request can access this endpoint
    user = request.args.get("user")
    return {"user": user, "data": "sensitive profile data"}


@app.route("/reset-password", methods=["POST"])
def reset_password():
    email = request.form.get("email")
    token = generate_reset_token(1)  # VULN: predictable token

    # VULN: Token sent in response body rather than via email — exposed in logs/proxies
    return {"reset_token": token, "message": f"Token for {email}"}
