import json

import requests
from flask import Blueprint, redirect, request
from flask_login import current_user, logout_user
from oauthlib.oauth2 import WebApplicationClient

from core.auth.oidc.user_management import authenticate
from core.config.config import yeti_config
from core.web.helpers import prevent_csrf

auth = Blueprint('auth', __name__, template_folder='templates')

client = WebApplicationClient(yeti_config.oidc.client_id)


@auth.route('/login', methods=['GET', 'POST'])
@prevent_csrf
def login():
    if current_user.is_authenticated:
        return redirect("/observable/")
    provider_cfg = get_google_provider_cfg()
    authorization_endpoint = provider_cfg['authorization_endpoint']

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=['openid', 'email', 'profile']
    )
    return redirect(request_uri)

@auth.route('/login/callback', methods=['GET', 'POST'])
def login_callback():
    code = request.args.get('code')

    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Send request for token with the  code received in the callback
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )

    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(yeti_config.oidc.client_id, yeti_config.oidc.client_secret),
    )

    client.parse_request_body_response(json.dumps(token_response.json()))
    # Our client can now get information on the user

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # userinfo_response.json().get("email_verified")
    # unique_id = userinfo_response.json()["sub"]
    user_email = userinfo_response.json()["email"]
    # picture = userinfo_response.json()["picture"]
    # users_name = userinfo_response.json()["given_name"]

    authenticate(user_email)
    return redirect('/')

@auth.route('/logout')
def logout():
    logout_user()
    return redirect('/')

def get_google_provider_cfg():
    discovery_url = yeti_config.oidc.google_discovery_url
    return requests.get(discovery_url).json()
