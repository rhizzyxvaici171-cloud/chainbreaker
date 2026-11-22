"""Vulnerable Shop: a deliberately insecure demo app for ChainBreaker.

Every weakness here is on purpose. DO NOT DEPLOY THIS.
"""
import sqlite3
import subprocess

import jwt
import yaml
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins="*", supports_credentials=True)

JWT_SECRET = "shop-signing-key-2024"


def db():
    return sqlite3.connect("shop.db")


@app.route("/login", methods=["POST"])
def login():
    user = request.json["user"]
    token = jwt.encode({"user": user, "role": "customer"}, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})


@app.route("/products")
def products():
    q = request.args.get("q", "")
    cur = db().cursor()
    cur.execute(f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'")
    return jsonify(cur.fetchall())


@app.route("/admin/users")
def admin_users():
    cur = db().cursor()
    cur.execute("SELECT id, email, role FROM users")
    return jsonify(cur.fetchall())


@app.route("/import", methods=["POST"])
def import_catalog():
    catalog = yaml.load(request.data)
    return jsonify({"imported": len(catalog)})


@app.route("/health/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
