"""A blueprint for google authentification routes"""
import json

import requests
from flask import Blueprint, request, make_response, redirect, url_for
from flask_login import login_user
from oauthlib.oauth2 import WebApplicationClient

from . import db
from .providers import google_provider
from .user import User

google_auth = Blueprint('google_auth', __name__)
client = WebApplicationClient(google_provider.client_id)


@google_auth.route('/login_with_google')
def login_with_google():
    """Route for login with Google provider"""
    # get auth endpoint from config
    authorisation_endpoint = google_provider.cfg["authorization_endpoint"]
    # prepare uri to redirect to google
    request_uri = client.prepare_request_uri(
        authorisation_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=['openid', 'email', 'profile'])
    # prepare response
    response = make_response(redirect(request_uri))
    # set cookie to know where to redirect back
    response.set_cookie('referrer', request.referrer)
    return response


@google_auth.route('/login_with_google/callback')
def google_callback():
    """
    Callback route for google auth.
    Gets the access code and exchanges for token.
    Requests the user information from Google
    """
    # Exchange access code on token
    auth_code = request.args.get('code')
    # get token endpoint from config
    token_endpoint = google_provider.cfg['token_endpoint']
    # prepare for request to get token
    token_uri, header, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=auth_code
    )
    # request token with client's id and secret
    token_response = requests.post(token_uri, headers=header, data=body,
                                   auth=(google_provider.client_id,
                                         google_provider.client_secret), timeout=3)
    client.parse_request_body_response(json.dumps(token_response.json()))
    # Get user information
    user_info_endpoint = google_provider.cfg["userinfo_endpoint"]
    uri, header, body = client.add_token(user_info_endpoint)
    user_info_response = requests.post(uri, headers=header, data=body, timeout=3).json()
    # check if the email was verified by google and it exists
    if user_info_response.get("email_verified"):
        user_email = user_info_response["email"]
        picture = user_info_response["picture"]
        user_name = user_info_response["given_name"]
    else:
        return "Email is not verified by Google or missed. Try again or register with EnvEd.", 400
    # Create a user object
    user = User.query.filter_by(email=user_email).first()
    if not user:
        user = User(email=user_email, profile_pic=picture, name=user_name, verified_email=1)
        db.session.add(user)
        db.session.commit()
    if not user.verified_email:
        user.verified_email = True
        db.session.commit()
    login_user(user)
    # code = generate_token(user)  # generate a jwt token
    redirect_to = request.cookies.get('referrer')  # get cookie with original referrer
    # redirect to the original website if cookie exists, otherwise to main page
    return redirect(redirect_to if redirect_to else url_for('main.index'))
