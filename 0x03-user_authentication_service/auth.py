#!/usr/bin/env python3
"""
Authentication file
"""
import bcrypt
from db import DB
from user import User
import uuid
from typing import Union


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

    def create_session(self, email: str):
        """
        Create a session for a user
        """
        try:
            user_id = self._db.find_user_by(email=email).id
        except Exception as e:
            return None
        session_id = _generate_uuid()
        try:
            self._db.update_user(user_id=user_id, session_id=session_id)
            return session_id
        except Exception as e:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """
        Find usr from session_id
        """
        try:
            return self._db.find_user_by(session_id=session_id)
        except Exception as e:
            return None

    def destroy_session(self, user_id: int) -> None:
        """
        Destroy user session
        """
        return self._db.update_user(user_id=user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """
        Get reset password token
        """
        user = self._db.find_user_by(email=email)
        if user is None:
            raise ValueError()
        else:
            reset_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def check_if_email_exists(self, email: str) -> bool:
        """
        Check user from email
        """
        user = self._db.find_user_by(email=email)
        if user is None:
            return False
        else:
            return True

    def update_password(self, reset_token: str, password: str) -> None:
        """
        This method id used to update the password
        """
        user = self._db.find_user_by(reset_token=reset_token)
        if user is None:
            raise ValueError
        else:
            hashed_password = _hash_password(password)
            self._db.update_user(user.id, reset_token=None,
                                 hashed_password=hashed_password)
