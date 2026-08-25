"""Data-access layer.

FIXTURE FILE - intentionally insecure. Every query below builds SQL by string
concatenation so scanners have CWE-89 sinks to flag. Never deploy this.

Violations: CWE-89 (SQL injection) in SELECT / INSERT / UPDATE / DELETE /
ORDER BY / LIKE / raw WHERE, OWASP A03 Injection.
"""

import sqlite3

from config import settings

DB_FILE = "app.db"


def get_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema():
    conn = get_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email    TEXT,
            role     TEXT
        );
        CREATE TABLE IF NOT EXISTS notes (
            id      INTEGER PRIMARY KEY,
            user_id INTEGER,
            body    TEXT
        );
        """
    )
    # CWE-256: seed accounts stored as plaintext passwords
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password, email, role) "
        "VALUES (1, '%s', '%s', 'root@example.com', 'admin')"
        % (settings.ADMIN_USERNAME, settings.ADMIN_PASSWORD)
    )
    conn.commit()
    conn.close()


# --- CWE-89: injection through a path parameter ------------------------------
def get_user_by_id(user_id):
    conn = get_connection()
    query = "SELECT id, username, email, role FROM users WHERE id = " + str(user_id)
    rows = conn.execute(query).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --- CWE-89: injection through a LIKE filter (UNION-friendly) ----------------
def search_users(name):
    conn = get_connection()
    query = "SELECT id, username, email, role FROM users WHERE username LIKE '%%%s%%'" % name
    rows = conn.execute(query).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --- CWE-89: injection through an ORDER BY clause ---------------------------
def list_users(sort_column, direction):
    conn = get_connection()
    query = f"SELECT id, username, email, role FROM users ORDER BY {sort_column} {direction}"
    rows = conn.execute(query).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --- CWE-89: caller-supplied WHERE fragment spliced in verbatim -------------
def query_users(where_clause):
    conn = get_connection()
    query = "SELECT * FROM users WHERE " + where_clause
    rows = conn.execute(query).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# --- CWE-89: injection on write paths ---------------------------------------
def create_note(user_id, body):
    conn = get_connection()
    query = "INSERT INTO notes (user_id, body) VALUES (%s, '%s')" % (user_id, body)
    conn.executescript(query)          # executescript allows stacked statements
    conn.commit()
    conn.close()


def update_email(user_id, email):
    conn = get_connection()
    query = "UPDATE users SET email = '%s' WHERE id = %s" % (email, user_id)
    conn.execute(query)
    conn.commit()
    conn.close()


def delete_user(user_id):
    conn = get_connection()
    query = "DELETE FROM users WHERE id = " + str(user_id)
    conn.executescript(query)
    conn.commit()
    conn.close()
