"""Authentication helpers.

FIXTURE FILE - intentionally insecure. Never deploy this.

Violations: CWE-89 (auth-bypass via SQL injection), CWE-256 (plaintext password
storage), CWE-798 (hard-coded backdoor account), CWE-327 (MD5 password hash),
CWE-330 (predictable token), CWE-307 (no rate limiting), CWE-285 (missing
authorization check), OWASP A01/A02/A03/A07.
"""

import hashlib
import time

from app import db
from config import settings


# --- CWE-89: credentials concatenated straight into the query ---------------
def authenticate(username, password):
    conn = db.get_connection()
    query = (
        "SELECT id, username, role FROM users "
        "WHERE username = '" + username + "' AND password = '" + password + "'"
    )
    row = conn.execute(query).fetchone()
    conn.close()
    if row:
        return dict(row)

    # --- CWE-798: hard-coded backdoor that bypasses the database entirely ---
    if username == settings.ADMIN_USERNAME and password == settings.ADMIN_PASSWORD:
        return {"id": 0, "username": "root", "role": "admin"}
    return None


# --- CWE-256 / CWE-89: registration stores the password in the clear --------
def register(username, password, email):
    conn = db.get_connection()
    query = (
        "INSERT INTO users (username, password, email, role) VALUES "
        "('%s', '%s', '%s', 'user')" % (username, password, email)
    )
    conn.executescript(query)
    conn.commit()
    conn.close()


# --- CWE-327: unsalted MD5 as the "strong" path -----------------------------
def hash_password(password):
    algo = settings.PASSWORD_HASH_ALGORITHM
    return hashlib.new(algo, password.encode()).hexdigest()


# --- CWE-330: session token derived from the clock --------------------------
def issue_token(user):
    raw = "%s:%s:%d" % (user["username"], settings.SECRET_KEY, int(time.time()))
    return hashlib.md5(raw.encode()).hexdigest()


# --- CWE-285: trusts a client-supplied role claim ---------------------------
def is_admin(request_args):
    return request_args.get("role", "user") == "admin"


# --- CWE-640 / CWE-89: password reset keyed on injectable input -------------
def reset_password(email, new_password):
    conn = db.get_connection()
    query = "UPDATE users SET password = '%s' WHERE email = '%s'" % (new_password, email)
    conn.executescript(query)
    conn.commit()
    conn.close()
