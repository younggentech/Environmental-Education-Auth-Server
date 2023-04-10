"""A Blueprint handling authentication routes"""
import datetime
import hashlib

from email_validator import validate_email, EmailNotValidError
from flask import Blueprint, request, redirect, url_for
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash

from . import db
from .tokens import generate_token, verify_token, Token
from .user import User, check_password

enved_auth = Blueprint('enved_auth', __name__)


@enved_auth.route('/signup', methods=['POST'])
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
    if 'name' not in userdata or 'email' not in userdata \
            or 'role' not in userdata or 'password' not in userdata:
        return 'name, email, role, password are required', 400
    # validate that the user doesn't exist
    if User.query.filter_by(email=userdata['email']).first():
        return 'User already exists', 400
    try:  # validate email and check deliverability
        validated_email = validate_email(userdata['email'],
                                         check_deliverability=True)
    except EmailNotValidError:
        return 'Not Valid Email', 400
    try:
        # create user
        user = User(name=userdata["name"], email=validated_email.email,
                    verified_email=0, role=userdata["role"],
                    password=generate_password_hash(userdata["password"]),
                    profile_pic="")
        db.session.add(user)
        db.session.commit()
        login_user(user)  # login user
        # generate token and return it with the user id
        return {"token": generate_token(user), "uid": user.id}
    except KeyError:
        return 'unavailable role', 400


@enved_auth.route('/login', methods=['POST'])
def login():
    """
    A backend method to handle authorisation with login and password.
    Alternative to Google login.
    Requred fields:
    email: str,
    password: str,
    Checks the credentials and issues a jwt token
    :return: json
    """
    userdata = request.json
    # check if reqiered fields are presented
    if 'email' not in userdata or 'password' not in userdata:
        return 'credentials are required', 403
    try:  # validate email
        validated_email = validate_email(userdata['email'],
                                         check_deliverability=False)
    except EmailNotValidError:
        return 'Not Valid Email', 400
    user = User.query.filter_by(email=validated_email.email).first()  # try to find user by email
    if not user:  # if no user found return 404
        return 'User Not Found', 404
    if not check_password(user.password, userdata["password"]):  # validate password
        return 'invalid credentials', 403
    login_user(user)
    # return jwt token and user id
    return {"token": generate_token(user), "uid": user.id}


@enved_auth.route('/verify', methods=["POST"])
def verify():
    """
    A route for token verification.
    Required field:
    token: str - original jwt token to be checked
    Returns json with "status" and "msg" fields.
    status:
    "Fail" - verification was not successfull
    "Verify" - email verification required
    "OK" - token is valid
    msg - explanation where was the problem
    """
    data = request.json
    if 'token' not in data:  # check if token field exists
        return 'No token provided', 400
    token = data["token"]
    verified = verify_token(token)
    print(verified)
    if not verified:  # checks if the token was signed by the server
        return {"status": "Fail", "msg": "unable to verify"}
    # checks if the token was blacklisted
    if Token.query.filter_by(token_hash=hashlib.sha256(token.encode()).hexdigest()).first():
        return {"status": "Fail", "msg": "token is blacklisted"}
    if verified['exp'] < datetime.datetime.now().timestamp():  # checks if token is expired
        return {"status": "Fail", "msg": "token is expired"}
    if not verified["verifiedEmail"]:
        return {"status": "Verify", "msg": "email verification required"}

    return {"status": "OK", "msg": "token is valid"}


@enved_auth.route("/logout")
@login_required
def logout():
    """Get request logout form with Flask-login"""
    logout_user()
    return redirect(url_for("main.index"))


@enved_auth.route("/logout", methods=["POST"])
def logout_post_request():
    """
    Backend logout method. Makes a token blacklisted and not valid.
    Required Fields:
    token: str - a jwt token to be annulated
    """
    data = request.json
    if 'token' not in data:  # check if required field exists
        return 'No token provided', 400
    token = data['token']
    verified = verify_token(token)
    if not verified:  # check if the token was verified successfully
        return "Invalid token", 400
    # check if the token wasn't blacklisted before
    if Token.query.filter_by(token_hash=hashlib.sha256(token.encode()).hexdigest()).first():
        return "Already blacklisted", 400
    try:  # blacklist the token
        new_token = Token(token_hash=hashlib.sha256(token.encode()).hexdigest(),
                          expiry_time=verified["exp"])
        db.session.add(new_token)
        db.session.commit()
        return {"status": "OK"}
    except Exception as error:
        print("logout", error)  # TODO: LOGGING
        return 'Try again later', 500
