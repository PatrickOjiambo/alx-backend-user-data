#!/usr/bin/env python3
"""
Hashing file
"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """
    Function for hashing a password
    """
    bytes_password = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(bytes_password, salt)
    return hashed_password
