"""Main Blueprint with routes about user and index"""
from flask import Blueprint
from flask_login import current_user, LoginManager

from .user import User

main = Blueprint('main', __name__)

login_manager = LoginManager()


# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    """Set up a function to load user for sessioning"""
    return User.query.filter_by(id=user_id).first()


@main.route("/")
def index():  # index route to be changed
    """Index View for the web-site"""
    if current_user.is_authenticated:
        return (
            f"<p>Hello, {current_user.name}! You're logged in! Email: {current_user.email}</p>"
            "<div><p>Google Profile Picture:</p>"
            f'<img src="{current_user.profile_pic}" alt="Google profile pic"></img></div>'
            '<a class="button" href="/logout">Logout</a>'
        )
    return '<a class="button" href="/login_with_google">Google Login</a>'
