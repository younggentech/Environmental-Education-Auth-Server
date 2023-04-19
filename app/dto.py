import dataclasses
import os
import typing as tp
import hashlib
import jwt

from sqlalchemy import exc

import app.user as user_model
import app.tokens as token_model
import app.main as constuctor


@dataclasses.dataclass
class Token:
    token_hash: str
    expiry_time: int
    @classmethod
    def generate_token(cls, user: user_model.User) -> str:
        """Generates jwt token and signs it with the secret key"""
        return jwt.encode(user_model.to_dict(user), os.environ.get("SECRET_KEY"), algorithm="HS256")
    
    @classmethod
    def decode_token(cls, token: str) -> tp.Tuple[bool, dict]:
        """Decodes token, verifies whether it is correct or not"""
        try:
            verified = jwt.decode(token, os.environ.get("SECRET_KEY"), algorithms="HS256")
        except jwt.exceptions.PyJWTError as error:
            print(error)  # TODO: LOGGING
            return False, {"status": "Fail", "msg": f"{error}"}
        return True, verified
    
    @classmethod
    def blacklist_token(cls, token: str) -> bool:
        """Method to put blacklisted tokens to db. only verified tokens are received"""
        try:
            new_token = token_model.Token(token_hash=hashlib.sha256(token.encode()).hexdigest(),
                            expiry_time=cls.decode_token(token)[1]["exp"])
            constuctor.db.session.add(new_token)
            constuctor.db.session.commit()
            return True
        except exc.DatabaseError:
            # TODO LOGGING
            return False
