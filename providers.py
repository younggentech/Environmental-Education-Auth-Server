import os
from typing import Optional

import requests

import jwt

from user import User


class Provider:
    """Class to store provider's data"""
    def __init__(self, client_id: str, client_secret: str):
        if client_id is None or client_secret is None:
            raise ValueError("Provider accepts only strings. None value was given. Check initialisation")
        self.client_id = client_id
        self.client_secret = client_secret


class GoogleProvider(Provider):
    """Class for auth with Google"""

    def __init__(self, client_id: str, client_secret: str):
        super().__init__(client_id, client_secret)
        # get configuration data
        self.cfg = requests.get("https://accounts.google.com/.well-known/openid-configuration").json()


# initialise a google provider with client id and secret from .env
google_provider = GoogleProvider(os.environ.get("GOOGLE_CLIENT_ID", None),
                                 os.environ.get("GOOGLE_CLIENT_SECRET", None),
                                 )


def generate_token(user: User) -> str:
    """Generates jwt token and signs it with the secret key"""
    return jwt.encode(user.to_dict(), os.environ.get("SECRET_KEY"), algorithm="HS256")


def verify_token(token: str) -> Optional[dict]:
    """Verifying token, whether it is correct or not"""
    try:
        verified = jwt.decode(token, os.environ.get("SECRET_KEY"), algorithms="HS256")
    except jwt.exceptions.InvalidSignatureError:
        return None
    return verified
