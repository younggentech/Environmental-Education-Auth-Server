import datetime

from email_validator import validate_email, EmailNotValidError
from flask import Blueprint, request, redirect, url_for
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash

from .providers import generate_token, verify_token
from .tokens import is_blacklisted, add_to_blacklist
from .user import User

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
    if 'name' not in userdata or 'email' not in userdata or 'role' not in userdata or 'password' not in userdata:
        return 'name, email, role, password are required', 400
    elif User.search_by_email(userdata['email']):  # validate that the user doesn't exist
        return 'User already exists', 400
    try:  # validate email and check deliverability
        validated_email = validate_email(userdata['email'], check_deliverability=True)
    except EmailNotValidError:
        return 'Not Valid Email', 400
    try:
        # create user
        User.create(name=userdata["name"], email=validated_email.email,
                    verified_email=0, role=userdata["role"],
                    password=generate_password_hash(userdata["password"]),
                    profile_pic="")
        user = User.search_by_email(validated_email.email)
    except Exception as e:
        print(e)  # TODO: LOG
        return 'Try again later', 500
    login_user(user)  # login user
    # generate token and return it with the user id
    return {"token": generate_token(user), "uid": user.id}


@enved_auth.route('/login', methods=['POST'])
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
    verified = verify_token(data["token"])
    print(verified)
    if not verified:  # checks if the token was signed by the server
        return {"status": "Fail", "msg": "unable to verify"}
    elif is_blacklisted(data["token"]):  # checks if the token was blacklisted
        return {"status": "Fail", "msg": "token is blacklisted"}
    elif verified['exp'] < datetime.datetime.now().timestamp():  # checks if token is expired
        return {"status": "Fail", "msg": "token is expired"}
    elif not verified["verifiedEmail"]:
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