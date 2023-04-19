"""Main Blueprint with routes about user and index"""
import flask
from flask_login import current_user, LoginManager

from app.user import User

main = flask.Blueprint('main', __name__)

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
            f'<a class="button" href="{flask.url_for("enved_auth.logout")}">Logout</a>'
        )
    return f'<a class="button" href="{flask.url_for("google_auth.login_with_google")}">Google Login</a>'
