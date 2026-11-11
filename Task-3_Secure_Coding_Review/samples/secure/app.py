"""CustomerPortal - SECURE version (remediated)."""
import json
import os
import re
import sqlite3
import subprocess
from functools import wraps
from pathlib import Path

import yaml
from flask import Flask, abort, request, send_from_directory, session, render_template_string
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]                 # from environment, never hardcoded
app.config.update(SESSION_COOKIE_HTTPONLY=True,
                  SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=os.environ.get("PROD") == "1")
DB = "portal.db"
UPLOAD_DIR = Path("uploads").resolve()
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


def db():
    return sqlite3.connect(DB)


def init_db():
    con = db()
    con.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)")
    con.execute("DELETE FROM users")
    for u, p, e, r in [("admin", "admin123", "admin@corp.com", "admin"),
                       ("alice", "alice123", "alice@corp.com", "user"),
                       ("bob", "bob123", "bob@corp.com", "user")]:
        con.execute("INSERT INTO users(username,password,email,role) VALUES (?,?,?,?)",
                    (u, generate_password_hash(p), e, r))   # salted, slow hash (scrypt/pbkdf2)
    con.commit()


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "uid" not in session:
            abort(401)
        return f(*a, **kw)
    return wrapper


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    return resp


@app.route("/login", methods=["POST"])
def login():
    u, p = request.form.get("username", ""), request.form.get("password", "")
    row = db().execute("SELECT id, role, password FROM users WHERE username=?", (u,)).fetchone()  # parameterized
    if row and check_password_hash(row[2], p):
        session.clear()
        session["uid"], session["role"] = row[0], row[1]
        return "Logged in"
    return "Invalid credentials", 401                       # generic message


@app.route("/profile/<int:uid>")
@login_required
def profile(uid):
    if uid != session["uid"] and session.get("role") != "admin":   # object-level authorization
        abort(403)
    row = db().execute("SELECT username,email FROM users WHERE id=?", (uid,)).fetchone()
    return {"username": row[0], "email": row[1]} if row else ("Not found", 404)


@app.route("/hello")
def hello():
    # user input passed as a template VARIABLE (auto-escaped), never concatenated into the template
    return render_template_string("<h1>Hello {{ name }}</h1>", name=request.args.get("name", ""))


@app.route("/ping")
@login_required
def ping():
    host = request.args.get("host", "127.0.0.1")
    if not HOST_RE.fullmatch(host) or host.startswith("-"):        # allow-list validation
        abort(400)
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5, shell=False)  # nosec B603 B607
    return out.stdout


@app.route("/download")
@login_required
def download():
    # send_from_directory rejects paths that escape UPLOAD_DIR
    return send_from_directory(UPLOAD_DIR, request.args.get("file", ""))


@app.route("/restore", methods=["POST"])
@login_required
def restore():
    try:
        return str(json.loads(request.form["data"]))        # JSON instead of pickle
    except (ValueError, KeyError):
        abort(400)


@app.route("/config", methods=["POST"])
@login_required
def config():
    try:
        return str(yaml.safe_load(request.form["yaml"]))    # safe_load
    except yaml.YAMLError:
        abort(400)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", debug=False)
