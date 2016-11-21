import os
import hmac
from hashlib import sha512

from flask import current_app
from werkzeug.security import check_password_hash, generate_password_hash

from core.user import User
from mongoengine import DoesNotExist


DEFAULT_PERMISSIONS = {
    "feed": {"read": True, "write": True, "toggle": True, "refresh": True},
    "observable": {"read": True, "write": True, "tag": True},
    "indicator": {"read": True, "write": True},
    "exporttemplate": {"read": True, "write": True},
    "entity": {"read": True, "write": True},
    "scheduledanalytics": {"read": True, "write": True, "toggle": True, "refresh": True},
    "oneshotanalytics": {"read": True, "write": True, "toggle": True, "run": True},
    "tag": {"read": True, "write": True},
    "export": {"read": True, "write": True},
    "files": {"read": True, "write": True},
    "link": {"read": True, "write": True},
    "neighbors": {"read": True, "write": True},
    "investigation": {"read": True, "write": True},
    "user": {"read": True, "write": True},
    "admin": True,
}


# This should be used for anonymous access
def get_default_user():
    try:
        return User.objects.get(username="yeti")
    except DoesNotExist:
        return create_user("yeti", "yeti")


def create_user(username, password, permissions=DEFAULT_PERMISSIONS):
    u = User(username=username, permissions=permissions)
    u = set_password(u, password)
    return u.save()


def authenticate(username, password):
    try:
        u = User.objects.get(username=username)
        if check_password_hash(u.password, password):
            return u
        else:
            return False
    except DoesNotExist:
        return False


def generate_session_token(user):
    key = current_app.config['SECRET_KEY']
    return hmac(key, (user.username + user.password + os.urandom(12).encode('hex')), sha512).hexdigest()


def set_password(user, password):
    user.password = generate_password_hash(password, method='pbkdf2:sha256:20000')
    user.api_key = User.generate_api_key()
    user.session_token = generate_session_token(user)
    return user
