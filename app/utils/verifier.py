"""A file containing business logic for verifying a token for /verify and /logout routes"""
import abc
import hashlib
import datetime
import typing as tp

import email_validator

from app import tokens, user
import app.dto as dto


class Verifier(abc.ABC):
    """An interface for a basic verifier"""
    @classmethod
    @abc.abstractmethod
    def verify(cls, data: dict) -> dict:
        """
        Method receives a token: str as a parameter 
        Returns json payload with information about token.
        status - always,
        msg - optional
        """
        raise NotImplementedError


class TokenVerifier(Verifier):
    """Verification used in /verify route"""
    @classmethod
    def verify(cls, data: dict) -> dict:
        if 'token' not in data:
            return {"code": 400, "status": "Fail", "msg": "no token provided"}
        token = data["token"]
        verification_status, verified = dto.Token.decode_token(token)
        print(verification_status, verified)  # TODO: LOGGING
        if not verification_status:  # checks if the token was signed by the server
            return verified
        # checks if the token was blacklisted
        if tokens.Token.query.filter_by(
                token_hash=hashlib.sha256(token.encode()).hexdigest()
                ).first():
            return {"status": "Fail", "msg": "token is blacklisted"}
        if verified['exp'] < datetime.datetime.now().timestamp():  # checks if token is expired
            return {"status": "Fail", "msg": "token is expired"}
        if not verified["verifiedEmail"]:
            return {"status": "Verify", "msg": "email verification required"}
        return {"status": "OK", "msg": "token is valid"}


class LogoutVerifier(Verifier):
    """Verification used in /logout route"""
    @classmethod
    def verify(cls, data: dict) -> dict:
        """
        Also returning token if token is valid
        """
        if 'token' not in data:
            return {"code": 400, "status": "Fail", "msg": "no token provided"}
        token = data["token"]
        verification_status, verified = dto.Token.decode_token(token)
        if not verification_status:  # check if the token was verified successfully
            return verified
        # check if the token wasn't blacklisted before
        if tokens.Token.query.filter_by(
            token_hash=hashlib.sha256(token.encode()).hexdigest()
            ).first():
            return {"status": "Fail", "msg": "Already blacklisted"}
        return {"status": "OK", "token": token}


class LoginVerifier(Verifier):
    """Verification used in /login route"""
    @classmethod
    def verify(cls, data: dict) -> dict:
        if 'email' not in data or 'password' not in data:
            return {"code": 400, "status": "Fail", "msg": "Credentials are required"}
        try:  # validate email
            validated_email = email_validator.validate_email(data['email'],
                                        check_deliverability=False)
        except email_validator.EmailNotValidError:
            return {"code": 400, "status": "Fail", "msg": "Not Valid Email"}
        fu: user.User = user.User.query.filter_by(email=validated_email.email).first()  # try to find user by email
        if not fu:  # if no user found return 404
            return {"code": 404, "status": "Fail", "msg": "User Not Found"}
        if not user.check_password(fu.password, data["password"]):  # validate password
            return {"code": 403, "status": "Fail", "msg": "invalid credentials"}
        return {"status": "OK", "uid": fu.id}
