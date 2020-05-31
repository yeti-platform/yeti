import hmac
import os
from binascii import hexlify
from hashlib import sha512

from flask import current_app
from flask_login import login_user
from flask_login.mixins import AnonymousUserMixin
from mongoengine.errors import DoesNotExist

from core.auth.local.user_management import DEFAULT_PERMISSIONS
from core.user import User

def get_default_user():
    return AnonymousUserMixin()

def authenticate(user_email):
    u = get_or_create_user(user_email)
    # u.session_token = generate_session_token(u)
    u.save()
    login_user(u)

    return u

def get_or_create_user(email):
    try:
        u = User.objects.get(username=email)
        u.enabled = True
        u.save()
    except DoesNotExist:
        u = create_user(email)
    return u

def create_user(email):
    u = User(username=email, permissions=DEFAULT_PERMISSIONS)
    u.api_key = User.generate_api_key()
    u.session_token = generate_session_token(u)
    u.enabled = True
    u.save()
    return u

def generate_session_token(user):
    # Also in local auth
    key = current_app.config['SECRET_KEY']
    return hmac.new(
        key, (user.username.encode() + hexlify(os.urandom(12))),
        sha512).hexdigest()
