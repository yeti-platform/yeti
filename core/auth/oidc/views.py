import json

import requests
from flask import Blueprint, abort, redirect, request, session
from flask_login import current_user, login_required, logout_user, login_user
from oauthlib.oauth2 import WebApplicationClient

from core.auth.oidc.group_management import create_group
from core.auth.oidc.user_management import get_or_create_user
from core.auth import common
from core.config.config import yeti_config
from core.web.helpers import prevent_csrf
from core.web.api.api import render

auth = Blueprint('auth', __name__)

client = WebApplicationClient(yeti_config.oidc.client_id)


@auth.route('/auth/login', methods=['GET', 'POST'])
@prevent_csrf
def login():
    provider_cfg = get_google_provider_cfg()
    authorization_endpoint = provider_cfg['authorization_endpoint']

    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=['openid', 'email', 'profile']
    )
    return redirect(request_uri)

@auth.route('/auth/login/callback', methods=['GET', 'POST'])
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

    user = get_or_create_user(user_email)
    common.generate_session_token(user)
    login_user(user)
    return redirect('/')

@auth.route('/auth/logout')
def logout():
    logout_user()
    session.clear()
    return redirect('/')

@auth.route('/api/creategroup', methods=["POST"])
@login_required
def api_new_group():
    params = request.get_json()
    groupname = params.get("groupname")
    if not current_user.has_role('admin') and current_user.is_active:
        abort(401)
    group = create_group(groupname)
    if not group:
        return render({'error': f'Group {groupname} already exists.'}), 400
    return render(group)

def get_google_provider_cfg():
    discovery_url = yeti_config.oidc.google_discovery_url
    return requests.get(discovery_url).json()
