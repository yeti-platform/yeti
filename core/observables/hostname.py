from __future__ import unicode_literals
import idna
from mongoengine import BooleanField, StringField

from core.observables import Observable
from core.helpers import is_hostname
from core.errors import ObservableValidationError


class Hostname(Observable):
    domain = BooleanField()
    idna = StringField()

    def clean(self):
        """Performs some normalization on hostnames before saving to the db"""
        try:
            self.normalize(self.value)
        except Exception:
            raise ObservableValidationError("Invalid hostname: {}".format(self.value))

    def normalize(self, hostname):
        if not is_hostname(hostname):
            raise ObservableValidationError("Invalid Hostname (is_hostname={}): {}".format(is_hostname(hostname), hostname))
        if hostname.endswith('.'):
            hostname = hostname[:-1]
        self.idna = unicode(idna.encode(hostname.lower()))
        self.value = unicode(idna.decode(hostname.lower()))
