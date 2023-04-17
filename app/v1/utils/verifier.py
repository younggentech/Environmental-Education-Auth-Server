"""A file containing business logic for verifying a token for /verify and /logout routes"""
import abc
import typing as tp
import hashlib
import datetime

from .. import tokens


class Verifier(abc.ABC):
    """An interface for a basic verifier"""
    @classmethod
    @abc.abstractmethod
    def verify(cls, token: str) -> dict:
        """
        Method receives a token: str as a parameter 
        Returns json payload with information about token.
        status:
        "Fail" - verification was not successfull
        "Verify" - email verification required
        "OK" - token is valid
        msg - explanation where was the problem
        """
        pass


class TokenVerifier(Verifier):
    """Verification used in /verify route"""
    @classmethod
    def verify(cls, token: str) -> dict:
        """
        Follows conventions from the interface
        """
        verification_status, verified = tokens.decode_token(token)
        print(verification_status, verified)  # TODO: LOGGING
        if not verification_status:  # checks if the token was signed by the server
            return verified
        # checks if the token was blacklisted
        if tokens.Token.query.filter_by(token_hash=hashlib.sha256(token.encode()).hexdigest()).first():
            return {"status": "Fail", "msg": "token is blacklisted"}
        if verified['exp'] < datetime.datetime.now().timestamp():  # checks if token is expired
            return {"status": "Fail", "msg": "token is expired"}
        if not verified["verifiedEmail"]:
            return {"status": "Verify", "msg": "email verification required"}
        return {"status": "OK", "msg": "token is valid"}


class LogoutVerifier(Verifier):
    """Verification used in /logout route"""
    @classmethod
    def verify(cls, token: str) -> dict:
        """
        Follows conventions from the interface
        """
        verification_status, verified = tokens.decode_token(token)
        if not verification_status:  # check if the token was verified successfully
            return verified
        # check if the token wasn't blacklisted before
        if tokens.Token.query.filter_by(token_hash=hashlib.sha256(token.encode()).hexdigest()).first():
            return {"status": "Fail", "msg": "Already blacklisted"}
        return {"status": "OK", "exp": verified["exp"]}