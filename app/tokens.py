"""
When logout occures, token is added to the blacklist, so it looses validity.
To ensure that database will not be full of unused tokens,
MySQL runs an event to delete expired tokens every 24 hours.
"""
from app.main import db


class Token(db.Model):
    """Token model for SQLAlchemy"""
    __tablename__ = 'BlackListedTokens'
    """User data model inherited from a flask-login user model"""
    token_hash = db.Column(db.String(70), primary_key=True)
    expiry_time = db.Column(db.Integer)
