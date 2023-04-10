from flask import Blueprint
from flask_login import current_user, LoginManager

from .user import User

main = Blueprint('main', __name__)

login_manager = LoginManager()


# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@main.route("/")
def index():  # index route to be changed
    """Index View for the web-site"""
    if current_user.is_authenticated:
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            "<div><p>Google Profile Picture:</p>"
            '<img src="{}" alt="Google profile pic"></img></div>'
            '<a class="button" href="/logout">Logout</a>'.format(
                current_user.name, current_user.email, current_user.profile_pic
            )
        )
    else:
        return '<a class="button" href="/login_with_google">Google Login</a>'
