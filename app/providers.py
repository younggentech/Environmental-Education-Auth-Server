"""
File keeps information about identity providers, each identity provider has a class with attributes.
"""

import os

import requests


class Provider:
    """
    Class to store provider's data.
    Attributes:
        client_id: str
        client_secret: str
    Raises:
        ValueError if one of the arguments is missed
    """
    def __init__(self, client_id: str, client_secret: str):
        if not client_id or not client_secret:
            raise ValueError(
                "Provider accepts only strings. None value was given. Check initialisation"
            )
        self.client_id = client_id
        self.client_secret = client_secret


class GoogleProvider(Provider):
    """
    Class for auth with Google.
    cfg: dict - json stores config data about google's endpoints.
    Requests information about endpoints using link
    https://accounts.google.com/.well-known/openid-configuration
    """

    def __init__(self, client_id: str, client_secret: str):
        super().__init__(client_id, client_secret)
        # get configuration data
        self.cfg = requests \
            .get("https://accounts.google.com/.well-known/openid-configuration", timeout=1) \
            .json()


# initialise a google provider with client id and secret from .env
google_provider = GoogleProvider(os.environ.get("GOOGLE_CLIENT_ID", None),
                                 os.environ.get("GOOGLE_CLIENT_SECRET", None))
