#!/usr/bin/env python3
"""
File for the flask APP
"""
from flask import Flask, jsonify
app = Flask(__name__)


@app.get("/", strict_slashes=False)
def index():
    """
    Simple get route
    """
    return jsonify({"message": "Bienvenue"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
