import os
import requests


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
        self.cfg = requests.get("https://accounts.google.com/.well-known/openid-configuration").json()


google_provider = GoogleProvider(os.environ.get("GOOGLE_CLIENT_ID", None),
                                 os.environ.get("GOOGLE_CLIENT_SECRET", None),
                                 )
