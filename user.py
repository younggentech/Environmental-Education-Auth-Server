from typing import Optional

from flask_login import UserMixin
from werkzeug.security import check_password_hash

from db import get_db


class User(UserMixin):
    def __init__(self, id_: int, name: str, email: str, verified_email: int, profile_pic: str,
                 role: Optional[str], password: Optional[str]):
        self.id = id_
        self.name = name
        self.email = email
        self.verified_email = verified_email
        self.role = role if role else None
        self.profile_pic = profile_pic
        self.password = password

    def check_password(self, psw):
        try:
            return check_password_hash(self.password, psw)
        except AttributeError:
            return False

    @staticmethod
    def get(user_id):
        db, connection = get_db()
        db.execute(
            "SELECT * FROM User WHERE id = %s", (user_id,)
        )
        user = db.fetchone()
        if not user:
            return None
        user = User(
            id_=user['id'],
            name=user['name'],
            email=user['email'],
            verified_email=user['verified_email'],
            role=user['role'],
            profile_pic=user['profile_pic'],
            password=user['password']
        )
        return user

    @staticmethod
    def search_by_email(email):
        db, connection = get_db()
        db.execute(
            "SELECT * FROM User WHERE email = %s", (email,)
        )
        user = db.fetchone()
        if not user:
            return None
        user = User(
            id_=user['id'],
            name=user['name'],
            email=user['email'],
            verified_email=user['verified_email'],
            role=user['role'],
            profile_pic=user['profile_pic'],
            password=user['password']
        )
        return user

    @staticmethod
    def create(id_, name, email, verified_email, profile_pic, role=None, password=None):
        db, connection = get_db()
        statement = 'INSERT INTO user (id, name, email, verified_email, role, profile_pic, password) ' \
                    'VALUES (%s, %s, %s, %s, %s, %s, %s)'
        db.execute(
            statement,
            (id_, name, email, verified_email, role, profile_pic, password),
        )
        connection.commit()

