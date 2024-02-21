#!/usr/bin/env python3
"""
File for the flask APP
"""
from flask import Flask, jsonify, request
from auth import Auth
app = Flask(__name__)

AUTH = Auth()


@app.route("/", methods=["GET"], strict_slashes=False)
def index():
    """
    Simple get route
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def users():
    """
    Endpoint for registering users
    """
    data = request.form
    try:
        AUTH.register_user(data['email'], data['password'])
        return jsonify({"email": data["email"], "message": "user created"})
    except Exception as e:
        return jsonify({"message": "email already registered"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
