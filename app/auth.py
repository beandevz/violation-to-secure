"""Authentication.

!!! INTENTIONALLY VULNERABLE SAMPLE - DO NOT USE IN PRODUCTION !!!
Violations: CWE-89 SQL Injection, CWE-798 Hard-coded credentials,
            CWE-256 Plaintext storage of passwords.
"""

from app.db import get_connection
from config.settings import ADMIN_PASSWORD, ADMIN_USERNAME


def login(username, password):
    """VIOLATION: CWE-89 - classic authentication bypass.

    Payload: username = "admin'--"  or  password = "' OR '1'='1"
    logs in without knowing any credential.
    """
    conn = get_connection()
    query = (
        "SELECT id, username, role FROM users "
        "WHERE username = '" + username + "' AND password = '" + password + "'"
    )
    row = conn.execute(query).fetchone()
    conn.close()
    return row


def register(username, password, email):
    """VIOLATION: CWE-89 injectable INSERT + CWE-256 password stored in plaintext."""
    conn = get_connection()
    conn.execute(
        f"INSERT INTO users (username, password, email, role) "
        f"VALUES ('{username}', '{password}', '{email}', 'user')"
    )
    conn.commit()
    conn.close()


def is_super_admin(username, password):
    """VIOLATION: CWE-798 - backdoor account compared against hard-coded values."""
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD


def reset_password(email, new_password):
    """VIOLATION: CWE-89 - no ownership check and injectable UPDATE."""
    conn = get_connection()
    conn.execute(
        "UPDATE users SET password = '%s' WHERE email = '%s'" % (new_password, email)
    )
    conn.commit()
    conn.close()
