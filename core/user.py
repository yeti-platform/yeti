from __future__ import unicode_literals

from mongoengine import StringField, DictField, BooleanField
from mongoengine import DoesNotExist
from flask_mongoengine.wtf import model_form
from werkzeug.security import check_password_hash, generate_password_hash

from core.database import YetiDocument

DEFAULT_ROLES = {
    "observables": ["read", "write", "tag"],
    "indicators": ["read", "write"],
    "entities": ["read", "write"],
    "admin": True,
}


class User(YetiDocument):
    available_settings = dict()

    username = StringField(required=True, unique=True)
    password = StringField(required=True)
    enabled = BooleanField(required=True, default=True)
    roles = DictField(verbose_name="Roles", default=DEFAULT_ROLES)
    settings = DictField(verbose_name="Settings")

    def is_authenticated(self):
        return self.enabled

    def is_admin(self):
        return self.roles.get('admin', False)

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return unicode(self.id)

    def has_settings(self, settings):
        for setting in settings:
            if setting not in self.settings:
                return False
        return True

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

    # This is only used because user management / access control is not yet implemented
    @staticmethod
    def get_default_user():
        return User.objects(username='yeti').modify(upsert=True, new=True, username='yeti', password="yeti")

    @staticmethod
    def create_user(username, password, roles=DEFAULT_ROLES):
        u = User(username=username, roles=roles)
        u.password = generate_password_hash(password)
        return u.save()

    @staticmethod
    def authenticate(username, password):
        try:
            u = User.objects.get(username=username)
            if check_password_hash(u.password, password):
                return u
            else:
                return False
        except DoesNotExist:
            return False
