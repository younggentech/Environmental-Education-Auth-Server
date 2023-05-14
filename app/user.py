"""Module stores User model, and functions connected to User"""
import datetime
from math import floor

from flask_login import UserMixin
from werkzeug.security import check_password_hash
from sqlalchemy_utils import ChoiceType
from app.main import db


class PendingUser(db.Model):
    """A tabble where unverified users are stored"""
    TYPES = [
        ('Student', 'Student'),
        ('Teacher', 'Teacher'),
        ('School', 'School')
    ]
    __tablename__ = 'PendingUser'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(200), unique=True, index=True)
    verified_email = db.Column(db.Boolean, default=False)
    role = db.Column(ChoiceType(TYPES))
    profile_pic = db.Column(db.String(200))
    password = db.Column(db.String(255))
    otp = db.Column(db.Integer)
    registration_time = db.Column(db.Integer)


class User(UserMixin, db.Model):
    """User data model for SQLAlchemy and Flask-login"""
    TYPES = [
        ('Student', 'Student'),
        ('Teacher', 'Teacher'),
        ('School', 'School'),
        ('TechAdmin', 'TechAdmin')
    ]
    __tablename__ = 'User'
    """User data model inherited from a flask-login user model"""
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(200), unique=True, index=True)
    role = db.Column(ChoiceType(TYPES))
    profile_pic = db.Column(db.String(200))
    password = db.Column(db.String(255))


def to_dict(user: User) -> dict:
    """Make a dict from an object to generate jwt token"""
    return {
        "sub": user.id,
        "name": user.name,
        "email": user.email,
        "role": str(user.role),
        "profilePic": user.profile_pic,
        "iat": floor(datetime.datetime.now().timestamp()),
        "exp": floor((datetime.datetime.now() + datetime.timedelta(hours=12)).timestamp())
    }


def check_password(real_psw: str, checked_psw: str) -> bool:
    """Checks if passwords match"""
    try:
        return check_password_hash(real_psw, checked_psw)
    except AttributeError:
        return False


def create_user_from_pending_user(email: str):
    """Creates a User from a PendingUser"""
    pu: PendingUser = PendingUser.query.filter_by(email=email).first()
    user = User(
        name=pu.name,
        email=pu.email,
        role=pu.role,
        profile_pic=pu.profile_pic,
        password=pu.password
    )
    db.session.delete(pu)
    db.session.add(user)
    db.session.commit()
