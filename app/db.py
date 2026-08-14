"""Data access layer.

!!! INTENTIONALLY VULNERABLE SAMPLE - DO NOT USE IN PRODUCTION !!!
Violation: CWE-89 SQL Injection.
Every query below builds SQL by concatenating or interpolating untrusted
input instead of using parameter binding.
"""

import sqlite3

from config.settings import DB_PASSWORD, DB_USER  # noqa: F401 - see settings.py

DB_FILE = "customers.db"


def get_connection():
    return sqlite3.connect(DB_FILE)


def init_db():
    conn = get_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            total REAL,
            status TEXT
        );
        """
    )
    conn.commit()
    conn.close()


def find_user_by_id(user_id):
    """VIOLATION: CWE-89 - f-string interpolation of request input.

    Payload: user_id = "1 OR 1=1" dumps the whole table.
    """
    conn = get_connection()
    query = f"SELECT id, username, email, role FROM users WHERE id = {user_id}"
    rows = conn.execute(query).fetchall()
    conn.close()
    return rows


def search_users(name):
    """VIOLATION: CWE-89 - string concatenation inside a LIKE clause.

    Payload: name = "x' UNION SELECT id, password, email, role FROM users--"
    """
    conn = get_connection()
    query = "SELECT id, username, email, role FROM users WHERE username LIKE '%" + name + "%'"
    rows = conn.execute(query).fetchall()
    conn.close()
    return rows


def list_orders(status, sort_column, direction):
    """VIOLATION: CWE-89 - untrusted input in both WHERE and ORDER BY."""
    conn = get_connection()
    query = (
        "SELECT id, user_id, total, status FROM orders "
        "WHERE status = '%s' ORDER BY %s %s" % (status, sort_column, direction)
    )
    rows = conn.execute(query).fetchall()
    conn.close()
    return rows


def update_email(user_id, new_email):
    """VIOLATION: CWE-89 - injectable UPDATE; also allows stacked statements.

    Payload: new_email = "x' WHERE 1=1--" rewrites every row.
    """
    conn = get_connection()
    conn.executescript(
        "UPDATE users SET email = '" + new_email + "' WHERE id = " + str(user_id)
    )
    conn.commit()
    conn.close()


def delete_user(username):
    """VIOLATION: CWE-89 - injectable DELETE via .format()."""
    conn = get_connection()
    conn.execute("DELETE FROM users WHERE username = '{}'".format(username))
    conn.commit()
    conn.close()


def run_report(raw_where):
    """VIOLATION: CWE-89 - raw SQL fragment accepted straight from the client."""
    conn = get_connection()
    rows = conn.execute("SELECT * FROM orders WHERE " + raw_where).fetchall()
    conn.close()
    return rows
