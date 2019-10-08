from __future__ import unicode_literals

from mongoengine import BooleanField, StringField, ListField, ReferenceField, CASCADE, EmbeddedDocument
from flask_mongoengine.wtf import model_form
from flask import url_for
from user import User
from core.database import YetiDocument

class Group(YetiDocument):
    enabled = BooleanField(required=True, default=True)
    groupname = StringField(required=True, unique=True)
    members = ListField(ReferenceField(User, reverse_delete_rule=CASCADE))
    admins = ListField(ReferenceField(User, reverse_delete_rule=CASCADE))

    SEARCH_ALIASES = {}
