#!/usr/bin/env python3
"""
Authentication file
"""
import bcrypt
from db import DB
from user import User
import uuid


def _hash_password(password: str) -> bytes:
    """
    Function for hashing a password
    """
    bytes_password = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(bytes_password, salt)
    return hashed_password


def _generate_uuid() -> str:
    """
    This function generates uuid
    """
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """
        function for registering a user
        """
        # Check if a user exists
        exists = self._db._session.query(User.id).filter_by(
            email=email).first() is not None
        if exists is True:
            raise ValueError("User {} already exists".format(email))
        hashed_password = _hash_password(password)
        return self._db.add_user(email, hashed_password)

    def valid_login(self, email: str, password: str) -> bool:
        """
        This function should validate logins
        """
        hashed_password = self._db._session.query(
            User.hashed_password).filter_by(email=email).first()
        if hashed_password is not None:
            result = bcrypt.checkpw(
                password.encode('utf-8'), hashed_password[0])
            return result
        return False
