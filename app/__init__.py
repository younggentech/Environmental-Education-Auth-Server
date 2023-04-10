import os

import dotenv
from flask import Flask
from mysql import connector


def create_app():
    dotenv.load_dotenv()
    # Flask app setup
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY")  # get a secret key from .env file

    from .main import main
    from .enved_auth import enved_auth
    from .google_auth import google_auth
    app.register_blueprint(main)
    app.register_blueprint(enved_auth)
    app.register_blueprint(google_auth)

    from .main import login_manager
    login_manager.init_app(app)

    # Naive database setup
    # from .db import init_db_command
    # try:
    #     init_db_command()
    # except connector.ProgrammingError:
    #     # Assume it's already been created
    #     print('Already created')

    return app
