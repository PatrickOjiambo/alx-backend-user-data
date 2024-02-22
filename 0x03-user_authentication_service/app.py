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


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout():
    """
    Endpoint for logging the user out
    """
    session_id = request.cookies.get('session_id')
    user_id = AUTH.get_user_from_session_id(session_id).id
    if user_id is not None:
        AUTH.destroy_session(user_id)
        return redirect("/")
    else:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
