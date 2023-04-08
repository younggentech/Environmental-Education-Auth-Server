# Python standard libraries
import datetime
import json
import os
from uuid import uuid4  # generating ids for users registered without Google

import mysql.connector as connector

# Third-party libraries
from email_validator import validate_email, EmailNotValidError  # library for email validation
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
from tokens import is_blacklisted, add_to_blacklist
from user import User
from providers import google_provider, generate_token, verify_token

# Flask app setup
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")  # get a secret key from .env file

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


@app.route('/signup', methods=['POST'])
def signup():
    """
    TODO: flow of the email verification with emailing microservice
    A backend method to create an account.
    Required fields (if something is missed returns error with status code 400):
    name: str,
    email: str,
    role: str = Student, or Teacher, or TechAdmin, or School
    password: str - password will be hashed
    :return: json
    """
    userdata = request.json
    # validate if all the necessary information is available
    if 'name' not in userdata or 'email' not in userdata or 'role' not in userdata or 'password' not in userdata:
        return 'name, email, role, password are required', 400
    elif User.search_by_email(userdata['email']):  # validate that the user doesn't exist
        return 'User already exists', 400
    try:  # validate email and check deliverability
        validated_email = validate_email(userdata['email'], check_deliverability=True)
    except EmailNotValidError:
        return 'Not Valid Email', 400
    try:
        id_ = str(uuid4())  # generate uuid for user id
        # create user
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
    login_user(user)  # login user
    # generate token and return it with the user id
    return {"token": generate_token(user), "uid": user.id}


@app.route('/login', methods=['POST'])
def login():
    """
    A backend method to handle authorisation with login and password. Alternative to Google login.
    Requred fields:
    email: str,
    password: str,
    Checks the credentials and issues a jwt token
    :return: json
    """
    userdata = request.json
    if 'email' not in userdata or 'password' not in userdata:  # check if reqiered fields are presented
        return 'credentials are required', 403
    try:  # validate email
        validated_email = validate_email(userdata['email'], check_deliverability=False)
    except EmailNotValidError:
        return 'Not Valid Email', 400
    user = User.search_by_email(validated_email.email)  # try to find user by email
    if not user:  # if no user found return 404
        return 'User Not Found', 404
    if not user.check_password(userdata["password"]):  # validate password
        return 'invalid credentials', 403
    login_user(user)
    # return jwt token and user id
    return {"token": generate_token(user), "uid": user.id}


@app.route('/login_with_google')
def login_with_google():
    """Route for login with Google provider"""
    authorisation_endpoint = google_provider.cfg["authorization_endpoint"]  # get auth endpoint from config
    # prepare uri to redirect to google
    request_uri = client.prepare_request_uri(
        authorisation_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=['openid', 'email', 'profile'])
    response = make_response(redirect(request_uri))  # prepare response
    response.set_cookie('referrer', request.referrer)  # set cookie to know where to redirect back
    return response


@app.route('/login_with_google/callback')
def google_callback():
    """
    Callback route for google auth.
    Gets the access code and exchanges for token.
    Requests the user information from Google
    """
    # Exchange access code on token
    auth_code = request.args.get('code')
    token_endpoint = google_provider.cfg['token_endpoint']  # get token endpoint from config
    # prepare for request to get token
    token_uri, header, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=auth_code
    )
    # request token with client's id and secret
    token_response = requests.post(token_uri, headers=header, data=body, auth=(google_provider.client_id,
                                                                               google_provider.client_secret))
    client.parse_request_body_response(json.dumps(token_response.json()))
    # Get user information
    user_info_endpoint = google_provider.cfg["userinfo_endpoint"]
    uri, header, body = client.add_token(user_info_endpoint)
    user_info_response = requests.post(uri, headers=header, data=body).json()
    if user_info_response.get("email_verified"):  # check if the email was verified by google and it exists
        google_id = user_info_response["sub"]  # get unique Google id
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
    code = generate_token(user)  # generate a jwt token
    redirect_to = request.cookies.get('referrer')  # get cookie with original referrer
    # redirect to the original website if cookie exists, otherwise to main page
    return redirect(redirect_to if redirect_to else url_for('index'))


@app.route('/verify', methods=["POST"])
def verify():
    """
    A route for token verification.
    Required field:
    token: str - original jwt token to be checked
    Returns json with "status" and "msg" fields.
    status:
    "Fail" - verification was not successfull
    "OK" - token is valid
    msg - explanation where was the problem
    """
    data = request.json
    if 'token' not in data:  # check if token field exists
        return 'No token provided', 400
    verified = verify_token(data["token"])
    if not verified:  # checks if the token was signed by the server
        return {"status": "Fail", "msg": "unable to verify"}
    elif is_blacklisted(data["token"]):  # checks if the token was blacklisted
        return {"status": "Fail", "msg": "token is blacklisted"}
    elif verified['exp'] < datetime.datetime.now().timestamp():  # checks if token is expired
        return {"status": "Fail", "msg": "token is expired"}
    return {"status": "OK", "msg": "token is valid"}


@app.route("/logout")
@login_required
def logout():
    """Get request logout form with Flask-login"""
    logout_user()
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
def logout_post_request():
    """
    Backend logout method. Makes a token blacklisted and not valid.
    Required Fields:
    token: str - a jwt token to be annulated
    """
    data = request.json
    if 'token' not in data:  # check if required field exists
        return 'No token provided', 400
    if not verify_token(data['token']):  # check if the token could be verified successfully
        return "Invalid token", 400
    if is_blacklisted(data["token"]):  # check if the token wasn't blacklisted before
        return "Already blacklisted", 400
    try:  # blacklist the token
        add_to_blacklist(data["token"])
        return {"status": "OK"}
    except Exception as e:
        print("logout", e)
        return 'Try again later', 500


if __name__ == "__main__":
    app.run(ssl_context="adhoc")
