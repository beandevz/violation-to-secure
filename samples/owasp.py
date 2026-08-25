"""5 OWASP Top 10 issues beyond injection/secrets. Fixture only - do not deploy."""
import os
import pickle
import subprocess

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/admin/delete")                               # 1. A01: no authz check
def delete_user():
    return db_delete(request.args["id"])


@app.route("/ping")                                       # 2. A03: command injection
def ping():
    return subprocess.check_output("ping -c1 " + request.args["host"], shell=True)


@app.route("/restore", methods=["POST"])                  # 3. A08: untrusted pickle
def restore():
    return str(pickle.loads(request.data))


@app.route("/fetch")                                      # 4. A10: SSRF
def fetch():
    return requests.get(request.args["url"], verify=False).text


@app.route("/files")                                      # 5. A01: path traversal
def read_file():
    return open(os.path.join("uploads", request.args["name"])).read()
