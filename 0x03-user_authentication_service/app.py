#!/usr/bin/env python3
"""
File for the flask APP
"""
from flask import Flask, jsonify, redirect, request, make_response, abort, Response
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
            resp.set_cookie("session_id", session_id)
            return resp
        elif is_logged_in is False:
            abort(401)
    except Exception as e:
        abort(401)


@app.route("/sessions", methods=["DELETE"])
def logout():
    """
    Endpoint for logging the user out
    """
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user is not None:
        AUTH.destroy_session(user.id)
        return redirect("/")
    else:
        abort(403)


@app.route("/profile", methods=["GET"], strict_slashes=False)
def profile():
    """
    profile endpoint
    """
    cookie = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(cookie)
    if user is None:
        abort(403)
    else:
        return jsonify({"email": user.email}), 200


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token():
    """
    endpoint to reset the password
    """
    data = request.form
    is_registered = AUTH.check_if_email_exists(data["email"])
    if is_registered is True:
        reset_token = AUTH.get_reset_password_token(data["email"])
        if not reset_token:
            abort(403)
        return jsonify({"email": data["email"], "reset_token": reset_token}), 200
    else:
        abort(403)


@app.route("/reset_password", methods=["PUT"])
def update_password():
    """
    endpoint to update passwords
    """
    data = request.form
    try:
        AUTH.update_password(data["reset_token"], data["new_password"])
        return jsonify({"email": data["email"], "message": "Password updated"}), 200
    except Exception as e:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
