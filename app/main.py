"""Flask front end - the taint sources for the sinks in app/db.py and app/auth.py.

FIXTURE FILE - intentionally insecure. Never deploy this.

Violations by OWASP Top 10 (2021):
  A01 Broken Access Control ....... /admin/users, /users/<id>/delete
  A02 Cryptographic Failures ...... plaintext passwords, MD5 tokens, no TLS
  A03 Injection ................... every /users route, /login, /ping (CWE-78)
  A04 Insecure Design ............. no rate limiting or lockout on /login
  A05 Security Misconfiguration ... DEBUG=True, 0.0.0.0, wildcard CORS
  A06 Vulnerable Components ....... pinned EOL versions in requirements.txt
  A07 Auth Failures ............... backdoor account, guessable session token
  A08 Integrity Failures .......... pickle.loads on user input (CWE-502)
  A09 Logging Failures ............ credentials written to the log
  A10 SSRF ........................ /fetch proxies any user-supplied URL
"""

import base64
import logging
import os
import pickle
import subprocess

import requests
from flask import Flask, jsonify, request

from app import auth, db
from config import settings

app = Flask(__name__)
app.secret_key = settings.SECRET_KEY          # CWE-798
logging.basicConfig(level=logging.DEBUG)


@app.after_request
def add_headers(response):
    # A05: wildcard CORS, no security headers
    response.headers["Access-Control-Allow-Origin"] = settings.CORS_ALLOW_ORIGIN
    response.headers["Server"] = "violation-to-secure/1.0 (python)"
    return response


# --- A03: SQL injection sinks ------------------------------------------------
@app.route("/users/<user_id>")
def get_user(user_id):
    return jsonify(db.get_user_by_id(user_id))


@app.route("/users/search")
def search_users():
    return jsonify(db.search_users(request.args.get("name", "")))


@app.route("/users")
def list_users():
    sort = request.args.get("sort", "id")
    direction = request.args.get("dir", "ASC")
    return jsonify(db.list_users(sort, direction))


@app.route("/users/query")
def query_users():
    # raw WHERE fragment straight from the query string
    return jsonify(db.query_users(request.args.get("where", "1=1")))


@app.route("/users/<user_id>/email", methods=["POST"])
def update_email(user_id):
    db.update_email(user_id, request.form.get("email", ""))
    return jsonify({"status": "ok"})


# --- A01: no authorization check on a destructive route ---------------------
@app.route("/users/<user_id>/delete", methods=["POST"])
def delete_user(user_id):
    db.delete_user(user_id)
    return jsonify({"status": "deleted"})


@app.route("/admin/users")
def admin_users():
    # A01: role read from the query string instead of the session
    if not auth.is_admin(request.args):
        return jsonify({"error": "forbidden"}), 403
    return jsonify(db.query_users("1=1"))


# --- A03 / A07: auth bypass, plus A09 credential logging --------------------
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    logging.info("login attempt user=%s password=%s", username, password)  # CWE-532
    user = auth.authenticate(username, password)          # A04: unlimited attempts
    if not user:
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({"user": user, "token": auth.issue_token(user)})


@app.route("/register", methods=["POST"])
def register():
    auth.register(
        request.form.get("username", ""),
        request.form.get("password", ""),      # CWE-256: stored in the clear
        request.form.get("email", ""),
    )
    return jsonify({"status": "created"})


@app.route("/reset", methods=["POST"])
def reset():
    auth.reset_password(request.form.get("email", ""), request.form.get("password", ""))
    return jsonify({"status": "reset"})


# --- CWE-78: OS command injection -------------------------------------------
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return out


# --- A10: SSRF, the URL is proxied unvalidated ------------------------------
@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    resp = requests.get(url, verify=settings.VERIFY_TLS)   # CWE-295 too
    return resp.text


# --- A08: deserialization of untrusted data ---------------------------------
@app.route("/session/restore", methods=["POST"])
def restore_session():
    blob = base64.b64decode(request.form.get("state", ""))
    return jsonify({"state": str(pickle.loads(blob))})     # CWE-502


# --- CWE-22: path traversal --------------------------------------------------
@app.route("/files")
def read_file():
    name = request.args.get("name", "README.md")
    with open(os.path.join("uploads", name)) as fh:
        return fh.read()


# --- CWE-200: secrets disclosed over HTTP -----------------------------------
@app.route("/debug/config")
def debug_config():
    return jsonify({k: str(v) for k, v in vars(settings).items() if k.isupper()})


# --- CWE-209: stack traces returned to the client ---------------------------
@app.errorhandler(500)
def server_error(exc):
    import traceback

    return jsonify({"error": str(exc), "trace": traceback.format_exc()}), 500


if __name__ == "__main__":
    db.init_schema()
    # A05: debug reloader + console exposed on every interface
    app.run(host=settings.BIND_HOST, port=settings.BIND_PORT, debug=settings.DEBUG)
