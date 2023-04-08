from typing import Optional

from flask_login import UserMixin
from db import get_db


class User(UserMixin):
    def __init__(self, id_: int, name: str, email: str, verified_email: int, profile_pic: str, role: Optional[str]):
        self.id = id_
        self.name = name
        self.email = email
        self.verified_email = verified_email
        self.role = role if role else None
        self.profile_pic = profile_pic

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
            profile_pic=user['profile_pic']
        )
        return user

    @staticmethod
    def create(id_, name, email, verified_email, profile_pic, role=None):
        db, connection = get_db()
        statement = 'INSERT INTO user (id, name, email, verified_email, role, profile_pic) ' \
                    'VALUES (%s, %s, %s, %s, %s, %s)'
        db.execute(
            statement,
            (id_, name, email, verified_email, role, profile_pic),
        )
        connection.commit()
