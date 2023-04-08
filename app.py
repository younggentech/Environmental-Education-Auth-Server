# Python standard libraries
import json
import os
from uuid import uuid4

import mysql.connector as connector

# Third-party libraries
from email_validator import validate_email, EmailNotValidError
from flask import Flask, redirect, request, url_for, jsonify, make_response
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import requests

# Internal imports
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash

from db import init_db_command
from user import User
from providers import google_provider

# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# User session management setup
# https://flask-login.readthedocs.io/en/latest
login_manager = LoginManager()
login_manager.init_app(app)

# Naive database setup
try:
    init_db_command()
except connector.ProgrammingError:
    # Assume it's already been created
    print('Already created')

# OAuth 2 client setup
client = WebApplicationClient(google_provider.client_id)


# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route("/")
def index():
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


@app.route('/signup', methods=['POST'])
def signup():
    userdata = request.json
    if 'name' not in userdata or 'email' not in userdata or 'role' not in userdata or 'password' not in userdata:
        return 'name, email, role, password are required', 400
    elif User.search_by_email(userdata['email']):
        return 'User already exists', 400
    try:
        validated_email = validate_email(userdata['email'], check_deliverability=True)
    except EmailNotValidError:
        return 'Not Valid Email', 400
    try:
        id_ = str(uuid4())
        user = User(id_=id_, name=userdata["name"], email=validated_email.email,
                    verified_email=0, role=userdata["role"],
                    password=generate_password_hash(userdata["password"]),
                    profile_pic="")
        User.create(id_=id_, name=userdata["name"], email=validated_email.email,
                    verified_email=0, role=userdata["role"],
                    password=generate_password_hash(userdata["password"]),
                    profile_pic="")
    except Exception as e:
        print(e)
        return 'Try again later', 500
    print(user)
    login_user(user)
    return redirect(url_for('index'))


@app.route('/login', methods=['POST'])
def login():
    userdata = request.json
    if 'email' not in userdata or 'password' not in userdata:
        return 'credentials are required', 403
    try:
        validated_email = validate_email(userdata['email'], check_deliverability=False)
    except EmailNotValidError:
        return 'Not Valid Email', 400
    user = User.search_by_email(validated_email.email)
    if not user.check_password(userdata["password"]):
        return 'invalid credentials', 403
    login_user(user)
    return redirect(url_for('index'))


@app.route('/login_with_google')
def login_with_google():
    authorisation_endpoint = google_provider.cfg["authorization_endpoint"]
    request_uri = client.prepare_request_uri(
        authorisation_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=['openid', 'email', 'profile'])
    response = make_response(redirect(request_uri))
    response.set_cookie('referrer', request.referrer)
    return response


@app.route('/login_with_google/callback')
def google_callback():
    """Callback route for google auth"""
    # Exchange access code on token
    auth_code = request.args.get('code')
    token_endpoint = google_provider.cfg['token_endpoint']
    token_uri, header, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=auth_code
    )
    token_response = requests.post(token_uri, headers=header, data=body, auth=(google_provider.client_id,
                                                                               google_provider.client_secret))
    client.parse_request_body_response(json.dumps(token_response.json()))
    # Get user information
    user_info_endpoint = google_provider.cfg["userinfo_endpoint"]
    uri, header, body = client.add_token(user_info_endpoint)
    user_info_response = requests.post(uri, headers=header, data=body).json()
    if user_info_response.get("email_verified"):
        google_id = user_info_response["sub"]
        user_email = user_info_response["email"]
        picture = user_info_response["picture"]
        user_name = user_info_response["given_name"]
    else:
        return "Email is not verified by Google or missed. Try again or register with EnvEd.", 400
    # Create a user object
    user = User(id_=google_id, email=user_email, profile_pic=picture, name=user_name, verified_email=1,
                role=None, password=None)
    if not User.get(google_id):
        User.create(id_=google_id, email=user_email, profile_pic=picture, name=user_name, verified_email=1)
    login_user(user)
    redirect_to = request.cookies.get('referrer')
    return redirect(redirect_to if redirect_to else url_for('index'))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(ssl_context="adhoc")
