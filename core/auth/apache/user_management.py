from os import urandom

from flask import request
from flask_login.mixins import AnonymousUserMixin
from mongoengine.errors import DoesNotExist

from core.config.config import yeti_config
from core.auth.local.user_management import DEFAULT_PERMISSIONS, generate_session_token
from core.user import User


def create_user(username):
    user = User(username=username, permissions=DEFAULT_PERMISSIONS)
    user.api_key = User.generate_api_key()
    user.password = urandom(24).encode("hex")
    user.session_token = generate_session_token(user)
    user.enabled = True
    user.save()
    return user


def authenticate():
    username = request.environ.get(yeti_config.auth.apache_variable)
    if username is None:
        return False
    try:
        return User.objects.get(username=username)
    except DoesNotExist:
        return create_user(username)


def get_default_user():
    user = authenticate()
    if not user:
        return AnonymousUserMixin()
    return user
