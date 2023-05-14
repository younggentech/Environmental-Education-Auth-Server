"""A Blueprint handling authentication routes"""
import json
import time

import flask
from email_validator import validate_email, EmailNotValidError
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash

from app import dto
from app.main import db
from app.user import User, PendingUser, create_user_from_pending_user, to_dict
from app.utils import verifier, publisher
from app.utils.otp import generate_otp


enved_auth = flask.Blueprint('enved_auth', __name__)


@enved_auth.route('/signup', methods=['POST', 'OPTIONS'])
async def signup():
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
    if flask.request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    userdata = flask.request.get_json(force=True)
    print(userdata)
    # validate if all the necessary information is available
    if 'name' not in userdata or 'email' not in userdata \
            or 'role' not in userdata or 'password' not in userdata:
        return {"status": "Fail", "msg": "Name, email, role, password are required"}, 400
    # validate that the user doesn't exist
    if User.query.filter_by(email=userdata['email']).first():
        return {"status": "Fail", "msg": "User already exists"}, 409
    if PendingUser.query.filter_by(email=userdata['email']).first():
        return {"status": "Verify"}
    try:  # validate email and check deliverability
        validated_email = validate_email(userdata['email'],
                                        check_deliverability=True)
    except EmailNotValidError:
        return {"status": "Fail", "msg": "Not Valid Email"}, 400
    try:
        # create verification code
        otp = generate_otp()
        # create user
        user = PendingUser(name=userdata["name"], email=validated_email.email,
                            verified_email=0, role=userdata["role"],
                            password=generate_password_hash(userdata["password"]),
                            profile_pic="", otp=otp, registration_time=int(time.time()))
        db.session.add(user)
        db.session.commit()
        await publisher.post_code({"to": validated_email.email, "code": otp})
        return {"status": "Verify"}
    except KeyError:
        return {"status": "Fail", "msg": "Unavailable Role"}, 400


@enved_auth.route('/login', methods=['POST', 'OPTIONS'])
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
    if flask.request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    verified = verifier.LoginVerifier.verify(flask.request.json)
    # check if reqiered fields are presented
    if not verified["status"] == "OK":
        return flask.Response(response=json.dumps(verified),
                                    status=verified.get('code', 200),
                                    mimetype='application/json')
    current_user = User.query.filter_by(id=verified["uid"]).first()
    login_user(current_user)
    return {"token": dto.Token.generate_token(current_user), **to_dict(current_user)}


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
    verified = verifier.TokenVerifier.verify(flask.request.json)
    if verified["status"] != "OK":
        return flask.Response(response=json.dumps(verified),
                                        status=verified.get('code', 200),
                                        mimetype='application/json')
    token = verified["token"]
    decoded = dto.Token.decode_token(token)[1]
    return {"token": token, **decoded}


@enved_auth.route('/revoke_token', methods=["POST", "OPTIONS"])
def revoke_toke():
    """
    Similar to verify, but after token is verified
    generates a new one and blacklists original token
    """
    if flask.request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    verified = verifier.TokenVerifier.verify(flask.request.json)
    if verified["status"] != "OK":
        return flask.Response(response=json.dumps(verified),
                              status=verified.get('code', 200),
                              mimetype='application/json')
    token = verified["token"]
    email = dto.Token.decode_token(token)[1]["email"]
    user = User.query.filter_by(email=email).first()
    dto.Token.blacklist_token(token)

    return {"token": dto.Token.generate_token(user), **to_dict(user)}


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


@enved_auth.route('/verify_account', methods=["POST", "OPTIONS"])
def verify_account():
    """
    Verify account with an email and OTP. If successfull, authorises the person.
    """
    if flask.request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    verified = verifier.VerifyAccount.verify(flask.request.json)
    if verified['status'] != "OK":
        return flask.Response(response=json.dumps(verified),
                              status=verified.get('code', 200),
                              mimetype='application/json')
    create_user_from_pending_user(verified["email"])
    user = User.query.filter_by(email=verified["email"]).first()
    return {"token": dto.Token.generate_token(user), **to_dict(user)}


@enved_auth.route('/resend_verification', methods=["POST", "OPTIONS"])
async def resend_verification():
    """Double send verification email if more than 2 minutes passed"""
    if flask.request.method == 'OPTIONS':
        return _build_cors_preflight_response()
    verified = verifier.ResendVerification.verify(flask.request.json)
    if verified['status'] != "OK":
        return flask.Response(response=json.dumps(verified),
                              status=verified.get('code', 200),
                              mimetype='application/json')
    pu: PendingUser = PendingUser.query.filter_by(email=verified["email"]).first()
    new_otp = generate_otp()
    pu.otp = new_otp
    pu.registration_time = time.time()
    db.session.commit()
    await publisher.post_code({"to": verified["email"], "code": new_otp})
    return {"status": "OK", "msg": "Email was sent again"}


@enved_auth.after_request
def add_headers(resp):
    """Headers adding after each response"""
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Credentials"] = True
    resp.headers["Content-Type"] = "application/json"
    return resp


def _build_cors_preflight_response():
    """Response to CORS prelight"""
    response = flask.make_response()
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add('Access-Control-Allow-Headers', "*")
    response.headers.add('Access-Control-Allow-Methods', "*")
    return response
