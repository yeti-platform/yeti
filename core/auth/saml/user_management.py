from flask_login import login_user
from mongoengine.errors import DoesNotExist

from core.user import User


def authenticate(session):
    saml_user_data = session["samlUserdata"]
    saml_name_id = session["samlNameId"]
    user = get_or_create_user(saml_name_id, saml_user_data)
    login_user(user)
    return user


def get_or_create_user(saml_name_id, saml_user_data):
    try:
        u = User.objects.get(username=saml_name_id)
    except DoesNotExist:
        u = create_user(saml_name_id, saml_user_data)
    return u


def create_user(saml_name_id, saml_user_data):
    u = User(username=saml_name_id)
    u.save()
    u = adjust_permissions(u, saml_user_data)
    return u


def adjust_permissions(u, saml_user_data):
    # this should include the logic for parsing saml_user_data to permissions
    return u
