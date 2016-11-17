import os

from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import make_secure_token

from core.user import User
from mongoengine import DoesNotExist


DEFAULT_PERMISSIONS = {
    "indicator": ["read", "write"],
    "observable": ["read", "write"],
    "tag": ["read", "write"],
    "entity": ["read", "write"],
    "feed": ["read", "write"],
    "analytics": ["read", "write"],
    "export": ["read", "write"],
    "exporttemplate": ["read", "write"],
    "files": ["read", "write"],
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
    return os.urandom(12).encode('hex') + make_secure_token(user.username + user.password)


def set_password(user, password):
    user.password = generate_password_hash(password, method='pbkdf2:sha256:20000')
    user.api_key = User.generate_api_key()
    user.session_token = generate_session_token(user)
    return user
