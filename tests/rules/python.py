import os
import pickle
import sqlite3
import subprocess

import hashlib
import jwt
import requests
import yaml
from flask import Flask, request, render_template_string, send_file
from markupsafe import escape
from werkzeug.utils import secure_filename

app = Flask(__name__)
db = sqlite3.connect(":memory:")
cur = db.cursor()


@app.route("/user")
def user():
    uid = request.args.get("id")
    # ruleid: python-sql-injection, python-sql-formatted-query
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")
    # ok: python-sql-injection
    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))
    return "ok"


def report(table):
    # ruleid: python-sql-formatted-query
    cur.execute("SELECT count(*) FROM " + table)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # ruleid: python-command-injection
    os.system("ping -c 1 " + host)
    # ruleid: python-command-injection, python-subprocess-shell-true
    subprocess.run(f"ping {host}", shell=True)
    # ok: python-command-injection
    subprocess.run(["ping", "-c", "1", host])
    # ok: python-subprocess-shell-true
    subprocess.run("ls -la", shell=True)
    return "ok"


@app.route("/calc")
def calc():
    # ruleid: python-code-injection
    return str(eval(request.args.get("expr")))


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    # ruleid: python-ssrf
    r = requests.get(url, timeout=5)
    # ok: python-ssrf
    requests.get("https://api.example.com/status", params={"q": url})
    return r.text


@app.route("/download")
def download():
    name = request.args.get("file")
    # ok: python-path-traversal
    send_file(os.path.join("/data", secure_filename(name)))
    # ruleid: python-path-traversal
    return send_file("/data/" + name)


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # ruleid: python-ssti
    render_template_string("<p>Hola " + name + "</p>")
    # ok: python-ssti
    render_template_string("<p>Hola {{ name }}</p>", name=name)
    # ok: python-reflected-xss
    return f"<p>Hola {escape(name)}</p>"


@app.route("/hi")
def hi():
    name = request.args.get("name", "")
    # ruleid: python-reflected-xss
    return f"<h1>Hola {name}</h1>"


def load(data, path):
    # ruleid: python-insecure-deserialization
    obj = pickle.loads(data)
    # ruleid: python-insecure-deserialization
    cfg = yaml.load(open(path))
    # ok: python-insecure-deserialization
    cfg = yaml.load(open(path), Loader=yaml.SafeLoader)
    # ok: python-insecure-deserialization
    cfg = yaml.safe_load(open(path))
    return obj, cfg


def call():
    # ruleid: python-tls-verification-disabled
    requests.get("https://internal", verify=False)
    # ok: python-tls-verification-disabled
    requests.get("https://internal")


def auth(token, key):
    # ruleid: python-jwt-signature-not-verified
    jwt.decode(token, options={"verify_signature": False})
    # ok: python-jwt-signature-not-verified
    return jwt.decode(token, key, algorithms=["HS256"])


def store(password):
    # ruleid: python-weak-password-hash
    return hashlib.md5(password.encode()).hexdigest()


def checksum(content):
    # ok: python-weak-password-hash
    return hashlib.sha256(content).hexdigest()


if __name__ == "__main__":
    # ruleid: python-flask-debug-enabled
    app.run(debug=True)
