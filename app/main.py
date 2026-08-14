"""HTTP entry points.

!!! INTENTIONALLY VULNERABLE SAMPLE - DO NOT USE IN PRODUCTION !!!
Untrusted request parameters flow straight into the SQL builders in app/db.py
and app/auth.py, giving a scanner a complete source -> sink taint path.
"""

from flask import Flask, jsonify, request

from app import auth, db
from config.settings import DEBUG, SECRET_KEY, STRIPE_API_KEY

app = Flask(__name__)
app.secret_key = SECRET_KEY  # VIOLATION: hard-coded session key


@app.route("/users/<user_id>")
def get_user(user_id):
    # SOURCE: URL path segment -> SINK: f-string SQL (CWE-89)
    return jsonify(db.find_user_by_id(user_id))


@app.route("/users/search")
def search():
    # SOURCE: query string -> SINK: concatenated LIKE clause (CWE-89)
    return jsonify(db.search_users(request.args.get("name", "")))


@app.route("/orders")
def orders():
    # SOURCE: query string -> SINK: injectable ORDER BY (CWE-89)
    return jsonify(
        db.list_orders(
            request.args.get("status", "open"),
            request.args.get("sort", "id"),
            request.args.get("dir", "ASC"),
        )
    )


@app.route("/reports")
def reports():
    # SOURCE: client-supplied SQL fragment -> SINK: raw WHERE clause (CWE-89)
    return jsonify(db.run_report(request.args.get("where", "1=1")))


@app.route("/login", methods=["POST"])
def do_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if auth.is_super_admin(username, password):  # VIOLATION: hard-coded backdoor
        return jsonify({"role": "superadmin"})
    user = auth.login(username, password)  # SINK: injectable auth query (CWE-89)
    return jsonify(user) if user else ("unauthorized", 401)


@app.route("/register", methods=["POST"])
def do_register():
    auth.register(
        request.form.get("username", ""),
        request.form.get("password", ""),
        request.form.get("email", ""),
    )
    return "created", 201


@app.route("/users/<user_id>/email", methods=["POST"])
def change_email(user_id):
    db.update_email(user_id, request.form.get("email", ""))
    return "ok"


@app.route("/debug/config")
def debug_config():
    # VIOLATION: CWE-200 - leaks a hard-coded secret over HTTP
    return jsonify({"stripe_key": STRIPE_API_KEY, "debug": DEBUG})


if __name__ == "__main__":
    db.init_db()
    # VIOLATION: debug server bound to all interfaces
    app.run(host="0.0.0.0", port=8080, debug=DEBUG)
