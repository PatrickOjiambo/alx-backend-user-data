#!/usr/bin/env python3
"""
File for the flask APP
"""
from flask import Flask, jsonify, request, make_response, abort, Response
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


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login():
    """
    Route for login to the app
    """
    data = request.form
    try:
        is_logged_in = AUTH.valid_login(data['email'], data['password'])
        if is_logged_in is True:
            session_id = AUTH.create_session(data["email"])
            resp = make_response(
                jsonify({"email": data["email"], "message": "logged in"}))
            print(resp)
            resp.set_cookie("session_id", session_id)
            print(resp)
            return resp
        elif is_logged_in is False:
            abort(401)
    except Exception as e:
        abort(401)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
