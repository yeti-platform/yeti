from __future__ import unicode_literals

import os
from binascii import hexlify

from flask import url_for
from flask_mongoengine.wtf import model_form
from mongoengine import StringField, DictField, BooleanField

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
        return self.permissions.get("admin", False)

    @property
    def is_active(self):
        return self.enabled

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        return self.session_token

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
        return "<User: {}>".format(self.username)

    @classmethod
    def get_form(klass):
        return model_form(User)

    @classmethod
    def register_setting(klass, id, name, description):
        klass.available_settings[id] = {"name": name, "description": description}

    @classmethod
    def get_available_settings(klass):
        # We have to load all OneShotAnalytics in order to make sure
        # available_settings are up to date
        from core.analytics import OneShotAnalytics

        list(OneShotAnalytics.objects)

        return klass.available_settings

    @staticmethod
    def generate_api_key():
        return hexlify(os.urandom(40)).decode()

    def info(self):
        i = {
            k: v
            for k, v in self._data.items()
            if k in ["username", "enabled", "permissions", "api_key"]
        }
        i["available_settings"] = self.available_settings
        i["settings"] = self.settings
        i["id"] = str(self.id)
        return i
