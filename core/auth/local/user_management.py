import hmac
import os
from binascii import hexlify
from hashlib import sha512

from flask import current_app
from flask_login.mixins import AnonymousUserMixin
from mongoengine import DoesNotExist
from werkzeug.security import check_password_hash, generate_password_hash

from core.logger import userLogger
from core.user import User

DEFAULT_PERMISSIONS = {
    "feed": {
        "read": True,
        "write": True,
        "toggle": True,
        "refresh": True
    },
    "observable": {
        "read": True,
        "write": True,
        "tag": True
    },
    "indicator": {
        "read": True,
        "write": True
    },
    "exporttemplate": {
        "read": True,
        "write": True
    },
    "entity": {
        "read": True,
        "write": True
    },
    "scheduledanalytics": {
        "read": True,
        "write": True,
        "toggle": True,
        "refresh": True
    },
    "oneshotanalytics": {
        "read": True,
        "write": True,
        "toggle": True,
        "run": True
    },
    "inlineanalytics": {
        "read": True,
        "write": True,
        "toggle": True
    },
    "tag": {
        "read": True,
        "write": True
    },
    "export": {
        "read": True,
        "write": True,
        "toggle": True,
        "refresh": True
    },
    "attachedfiles": {
        "read": True,
        "write": True
    },
    "file": {
        "read": True,
        "write": True
    },
    "link": {
        "read": True,
        "write": True
    },
    "neighbors": {
        "read": True,
        "write": True
    },
    "investigation": {
        "read": True,
        "write": True
    },
    "user": {
        "read": True,
        "write": True
    },
    "admin": True,
}


def get_default_user():
    try:
        # Assume authentication is anonymous if only 1 user
        if User.objects.count() < 2:
            userLogger.info("Default user logged in : yeti")
            return User.objects.get(username="yeti")
        return AnonymousUserMixin()
    except DoesNotExist:
        return create_user("yeti", "yeti", admin=True)


def create_user(username, password, admin=False, permissions=DEFAULT_PERMISSIONS):
    permissions["admin"] = admin
    u = User(username=username, permissions=permissions)
    u = set_password(u, password)
    return u.save()


def authenticate(username, password):
    try:
        u = User.objects.get(username=username)
        if check_password_hash(u.password, password):
            userLogger.info("User logged in : %s",username)
            return u
        else:
            userLogger.warn("Attempt to log in to : %s",username)
            return False
    except DoesNotExist:
        return False


def generate_session_token(user):
    key = current_app.config['SECRET_KEY']
    return hmac.new(
        key, (user.username.encode() + user.password.encode() + hexlify(os.urandom(12))),
        sha512).hexdigest()


def set_password(user, password):
    user.password = generate_password_hash(
        password, method='pbkdf2:sha256:20000')
    user.api_key = User.generate_api_key()
    user.session_token = generate_session_token(user)
    userLogger.info("User password changed : %s",user.username)
    return user
