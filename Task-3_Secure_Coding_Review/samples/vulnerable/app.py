"""CustomerPortal - INTENTIONALLY VULNERABLE (for secure code review training only)."""
import hashlib
import os
import pickle
import base64
import sqlite3
import yaml
from flask import Flask, request, session, render_template_string, send_file

app = Flask(__name__)
app.secret_key = "supersecret123"            # hardcoded secret
DB = "portal.db"


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
                    (u, hashlib.md5(p.encode()).hexdigest(), e, r))   # weak hash, no salt
    con.commit()


@app.route("/login", methods=["POST"])
def login():
    u, p = request.form["username"], request.form["password"]
    h = hashlib.md5(p.encode()).hexdigest()
    q = f"SELECT id, role FROM users WHERE username='{u}' AND password='{h}'"   # SQL injection
    row = db().execute(q).fetchone()
    if row:
        session["uid"], session["role"] = row
        return "Logged in"
    return "Invalid credentials", 401


@app.route("/profile/<int:uid>")
def profile(uid):
    # no check that uid == session user -> IDOR / broken access control
    row = db().execute("SELECT username,email FROM users WHERE id=?", (uid,)).fetchone()
    return {"username": row[0], "email": row[1]} if row else ("Not found", 404)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    return render_template_string("<h1>Hello " + name + "</h1>")     # XSS + SSTI


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return os.popen("ping -c 1 " + host).read()                      # command injection


@app.route("/download")
def download():
    return send_file(os.path.join("uploads", request.args["file"]))  # path traversal


@app.route("/restore", methods=["POST"])
def restore():
    obj = pickle.loads(base64.b64decode(request.form["data"]))       # insecure deserialization
    return str(obj)


@app.route("/config", methods=["POST"])
def config():
    return str(yaml.load(request.form["yaml"], Loader=yaml.Loader))  # unsafe YAML load


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", debug=True)                              # debug on, all interfaces
