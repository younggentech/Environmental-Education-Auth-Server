"""A Blueprint handling authentication routes"""
import json
import flask
from email_validator import validate_email, EmailNotValidError
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash

from app import dto
from app.main import db
from app.tokens import Token
from app.user import User, check_password, PendingUser
from app.utils import verifier

enved_auth = flask.Blueprint('enved_auth', __name__)


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
    userdata = flask.request.json
    # validate if all the necessary information is available
    if 'name' not in userdata or 'email' not in userdata \
            or 'role' not in userdata or 'password' not in userdata:
        return 'name, email, role, password are required', 400
    # validate that the user doesn't exist
    if User.query.filter_by(email=userdata['email']).first():
        return 'User already exists', 409
    if PendingUser.query.filter_by(email=userdata['email']).first():
        return {"status": "Verify"}
    try:  # validate email and check deliverability
        validated_email = validate_email(userdata['email'],
                                        check_deliverability=True)
    except EmailNotValidError:
        return 'Not Valid Email', 400
    try:
        # create user
        user = PendingUser(name=userdata["name"], email=validated_email.email,
                            verified_email=0, role=userdata["role"],
                            password=generate_password_hash(userdata["password"]),
                            profile_pic="")
        db.session.add(user)
        db.session.commit()
        # generate verification code
        # call emailing service
        # generate token and return it with the user id
        return {"status": "Verify"}
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
    returns json
    """
    verified = verifier.LoginVerifier.verify(flask.request.json)
    # check if reqiered fields are presented
    if not verified["status"] == "OK":
        return flask.Response(response=json.dumps(verified),
                                    status=verified.get('code', 200),
                                    mimetype='application/json')
    current_user = User.query.filter_by(id=verified["uid"]).first()
    login_user(current_user)
    # return jwt token and user id
    return {"token": dto.Token.generate_token(current_user), "uid": current_user.id}


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
    """
    verified= verifier.TokenVerifier.verify(flask.request.json)
    return flask.Response(response=json.dumps(verified),
                                    status=verified.get('code', 200),
                                    mimetype='application/json')


@enved_auth.route("/logout")
@login_required
def logout():
    """Get request logout form with Flask-login"""
    logout_user()
    return flask.redirect(flask.url_for("main.index"))


@enved_auth.route("/logout", methods=["POST"])
def logout_post_request():
    """
    Backend logout method. Makes a token blacklisted and not valid.
    Required Fields:
    token: str - a jwt token to be annulated
    """
    verified = verifier.LogoutVerifier.verify(flask.request.json)
    if verified["status"] != "OK":
        return flask.Response(response=json.dumps(verified),
                                    status=verified.get('code', 200),
                                    mimetype='application/json')

    if not dto.Token.blacklist_token(verified['token']):
        return flask.Response(response=json.dumps({"code": 500, "status": "Fail", "msg": "server-side error"}),
                                    status=500,
                                    mimetype='application/json')
    return {"status": "ok", "msg": ""}
