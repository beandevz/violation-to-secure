"""5 SQL injection issues (CWE-89 / OWASP A03). Fixture only - do not deploy."""
import sqlite3

conn = sqlite3.connect("app.db")


def get_user(user_id):                                    # 1. concatenated id
    return conn.execute("SELECT * FROM users WHERE id = " + user_id).fetchall()


def search(name):                                         # 2. %-format in LIKE
    return conn.execute("SELECT * FROM users WHERE name LIKE '%%%s%%'" % name).fetchall()


def list_users(sort):                                     # 3. f-string ORDER BY
    return conn.execute(f"SELECT * FROM users ORDER BY {sort}").fetchall()


def set_email(user_id, email):                            # 4. injectable UPDATE
    conn.execute("UPDATE users SET email = '{}' WHERE id = {}".format(email, user_id))


def delete(where):                                        # 5. raw WHERE, stacked stmts
    conn.executescript("DELETE FROM users WHERE " + where)
