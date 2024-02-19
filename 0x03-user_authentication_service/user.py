#!/usr/bin/env python3
# type: ignore
"""
User table class
"""

from typing import Any
from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base


Base: Any = declarative_base()


class User(Base):
    """
    User table

    id, the integer primary key
    email, a non-nullable string
    hashed_password, a non-nullable string
    session_id, a nullable string
    reset_token, a nullable string

    """
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    session_id = Column(String, nullable=True)
    reset_token = Column(String, nullable=True)
