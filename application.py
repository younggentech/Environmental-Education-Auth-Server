"""Initiates the flask app with create_app() factory and runs it"""
from app.v1 import create_app

application = create_app()

if __name__ == '__main__':
    application.run(ssl_context="adhoc")
