"""
When logout occures, token is added to the blacklist, so it looses validity.
To ensure that database will not be full of unused tokens, MySQL runs an event to delete expired tokens every 24 hours.
"""
import datetime
import hashlib  # used to hash the token (sha256)
import os

import jwt

from db import get_db  # used to get cursor and connection


def is_blacklisted(token: str) -> bool:
    """Checks if token is in the blacklist. True if yes, otherwise false"""
    cursor, connection = get_db()  # get cursor and connection from g object
    hashed_token = hashlib.sha256(token.encode()).hexdigest()  # hash token, so it only takes 64 charactors
    cursor.execute("SELECT * FROM BlackListedTokens WHERE TokenHash = %s", (hashed_token,))  # execute select statement
    data = cursor.fetchone()  # get result set
    if data:  # if anything in the result, return True
        return True
    return False  # if the token is not in the result return False


def add_to_blacklist(token: str) -> bool:
    """Adds a token to the blacklist. Returns True if no exceptions were raised"""
    try:
        cursor, connection = get_db()  # get cursor and connection from g object
        hashed_token = hashlib.sha256(token.encode()).hexdigest()  # hash token, so it only takes 64 charactors
        # get expiry time from a decoded token
        expiry_time = jwt.decode(token, os.environ.get("SECRET_KEY"), algorithms="HS256")["exp"]
        if expiry_time < datetime.datetime.now().timestamp():  # if the token expired we don't need to blacklist it.
            return True
        cursor.execute("INSERT INTO BlackListedTokens (TokenHash, ExpiryTime) VALUES (%s, %s)",
                       (hashed_token, expiry_time))  # execute insert statement
        connection.commit()  # commit deletion
        return True
    except Exception as e:
        print('add_to_blacklist', e)
        raise Exception("Error in add_to_blacklist")
