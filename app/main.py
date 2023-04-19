"""An app factory file"""
import os

from flask_sqlalchemy import SQLAlchemy
import dotenv
from flask import Flask

db = SQLAlchemy()


def create_app() -> Flask:
    """Application factory method"""
    dotenv.load_dotenv()
    # Flask app setup
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY")  # get a secret key from .env file
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("SQLALCHEMY_DATABASE_URI")
    db.init_app(app)
    from .tokens import Token
    from .user import User
    with app.app_context():
        db.create_all()

    from .api.v1.main import main
    from .api.v1.enved_auth import enved_auth
    from .api.v1.google_auth import google_auth
    app.register_blueprint(main)
    app.register_blueprint(enved_auth, url_prefix='/v1')
    app.register_blueprint(google_auth)

    from .api.v1.main import login_manager
    login_manager.init_app(app)
    return app
