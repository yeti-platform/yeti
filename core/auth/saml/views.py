from urlparse import urlparse
import os

from flask import Blueprint, request, redirect, session
from flask_login import logout_user
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from web.views.helpers import prevent_csrf
from web.auth.saml.user_management import authenticate


auth = Blueprint('auth', __name__, template_folder='templates')


def init_saml_auth(req):
    saml_auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), 'saml/config'))
    return saml_auth


def prepare_auth_request(request):
    url_data = urlparse(request.url)
    return {
        "https": 'on',
        'http_host': request.host,
        'server_port': url_data.port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'query_string': request.query_string
    }


@auth.route('/saml/acs', methods=['GET', 'POST'])
def acs():
    req = prepare_auth_request(request)
    saml_auth = init_saml_auth(req)
    saml_auth.process_response()
    errors = saml_auth.get_errors()

    if len(errors) == 0:  # No errors, let's authenticate the user
        session['samlUserdata'] = saml_auth.get_attributes()
        session['samlNameId'] = saml_auth.get_nameid()
        session['samlSessionIndex'] = saml_auth.get_session_index()
        authenticate(session)
        self_url = OneLogin_Saml2_Utils.get_self_url(req)

        if 'RelayState' in request.form and self_url != request.form['RelayState']:
            return redirect(saml_auth.redirect_to(request.form['RelayState']))


@auth.route('/login', methods=['GET', 'POST'])
@prevent_csrf
def login():
    req = prepare_auth_request(request)
    saml_auth = init_saml_auth(req)

    redir = request.args.get('next', '/')

    if "/login" in redir:
        redir = '/'

    return redirect(saml_auth.login(redir))


@auth.route('/logout')
def logout():
    req = prepare_auth_request(request)
    saml_auth = init_saml_auth(req)
    logout_user()
    return redirect(saml_auth.logout(name_id=session['samlNameId'], session_index=session['samlSessionIndex']))
