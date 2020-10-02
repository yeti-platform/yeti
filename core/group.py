from __future__ import unicode_literals

from mongoengine import BooleanField, StringField, ListField, ReferenceField, CASCADE

from core.database import YetiDocument
from core.user import User


class Group(YetiDocument):
    enabled = BooleanField(required=True, default=True)
    groupname = StringField(required=True, unique=True)
    members = ListField(ReferenceField(User, reverse_delete_rule=CASCADE))
    admins = ListField(ReferenceField(User, reverse_delete_rule=CASCADE))

    SEARCH_ALIASES = {}
