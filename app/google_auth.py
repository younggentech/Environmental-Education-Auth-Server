import json

import requests
from flask import Blueprint, request, make_response, redirect, url_for
from flask_login import login_user
from oauthlib.oauth2 import WebApplicationClient

from .providers import google_provider, generate_token
from .user import User

google_auth = Blueprint('google_auth', __name__)
client = WebApplicationClient(google_provider.client_id)


@google_auth.route('/login_with_google')
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


@google_auth.route('/login_with_google/callback')
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
    user = User.search_by_email(user_email)
    if not user:
        User.create(email=user_email, profile_pic=picture, name=user_name, verified_email=1)
        user = User.search_by_email(user_email)
    if not user.verified_email:
        user.verify_email()
    login_user(user)
    code = generate_token(user)  # generate a jwt token
    redirect_to = request.cookies.get('referrer')  # get cookie with original referrer
    # redirect to the original website if cookie exists, otherwise to main page
    return redirect(redirect_to if redirect_to else url_for('main.index'))
