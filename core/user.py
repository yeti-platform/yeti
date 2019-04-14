from __future__ import unicode_literals

import os

from mongoengine import StringField, DictField, BooleanField, ListField, ReferenceField, CASCADE, NotUniqueError
from flask_mongoengine.wtf import model_form
from flask import url_for

from core.database import YetiDocument

class User(YetiDocument):
    available_settings = dict()

    username = StringField(required=True, unique=True)
    password = StringField()
    enabled = BooleanField(required=True, default=True)
    permissions = DictField(verbose_name="Permissions")
    settings = DictField(verbose_name="Settings")
    api_key = StringField(required=True, unique=True)
    session_token = StringField()

    SEARCH_ALIASES = {}

    @property
    def is_authenticated(self):
        return self.enabled

    @property
    def is_admin(self):
        return self.permissions.get('admin', False)

    @property
    def is_active(self):
        return self.enabled

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self.session_token)

    def has_settings(self, settings):
        for setting in settings:
            if setting not in self.settings:
                return False
        return True

    def has_permission(self, object_name, permission):
        return self.permissions.get(object_name, {}).get(permission)

    def has_role(self, role):
        return self.permissions.get(role, False)

    def __unicode__(self):
        return u"<User: {}>".format(self.username)

    @classmethod
    def get_form(klass):
        return model_form(User)

    @classmethod
    def register_setting(klass, id, name, description):
        klass.available_settings[id] = {
            'name': name,
            'description': description
        }

    @classmethod
    def get_available_settings(klass):
        # We have to load all OneShotAnalytics in order to make sure
        # available_settings are up to date
        from core.analytics import OneShotAnalytics
        list(OneShotAnalytics.objects)

        return klass.available_settings

    @staticmethod
    def generate_api_key():
        return os.urandom(40).encode('hex')

    def info(self):
        i = {
            k: v
            for k, v in self._data.items()
            if k in ["username", "enabled", "permissions", "api_key"]
        }
        i['url'] = url_for(
            "api.UserAdmin:post", id=str(self.id), _external=True)
        i['human_url'] = url_for(
            "frontend.UsersView:profile", id=str(self.id), _external=True)
        return i

class Group(YetiDocument):
    groupname = StringField(required=True, unique=True)
    members = ListField(ReferenceField(User, reverse_delete_rule=CASCADE))

    @staticmethod
    def get_user_groups(username):
        return Group.objects(members__in=[username])

    def create_group(groupname):
        try:
            return Group(groupname=groupname).save()
        except NotUniqueError:
            return False

    def delete_groups(groupname):
        return Group.objects(type=groupname).delete()

    def get_groups():
        return Group.objects()

    def add_user_to_group(groupname, user_id):
        return Group.objects(groupname=groupname).update_one(push__members=user_id)

    def del_user_from_group(groupname, username):
        return Group.objects(groupname=groupname).update_one(pull__members=username)

