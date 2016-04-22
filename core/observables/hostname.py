from __future__ import unicode_literals
import re

import idna
from mongoengine import BooleanField, StringField
from tldextract import extract

from core.observables import Observable
from core.helpers import refang
from core.errors import ObservableValidationError


class Hostname(Observable):

    regex = r"((.+\.)(.+))\.?"

    domain = BooleanField()
    idna = StringField()

    def clean(self):
        """Performs some normalization on hostnames before saving to the db"""
        try:
            self.normalize(self.value)
        except Exception:
            raise ObservableValidationError("Invalid hostname: {}".format(self.value))

    def normalize(self, hostname):
        if not Hostname.is_hostname(hostname):
            raise ObservableValidationError("Invalid Hostname (is_hostname={}): {}".format(Hostname.is_hostname(hostname), hostname))
        if hostname.endswith('.'):
            hostname = hostname[:-1]
        self.idna = unicode(idna.encode(hostname.lower()))
        self.value = unicode(idna.decode(hostname.lower()))

    @staticmethod
    def check_type(txt):
        hostname = refang(txt.lower())
        if hostname:
            match = re.match("^" + Hostname.regex + "$", hostname)
            if match:
                if hostname.endswith('.'):
                    hostname = hostname[:-1]

                parts = extract(hostname)
                if parts.suffix and parts.domain:
                    return hostname

        return False
