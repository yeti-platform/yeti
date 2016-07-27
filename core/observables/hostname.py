from __future__ import unicode_literals

import idna
from mongoengine import BooleanField, StringField
from tldextract import extract

from core.observables import Observable
from core.helpers import refang


class Hostname(Observable):

    main_regex = r'[-.\w[\]]+\[?\.\]?[\w]+'
    regex = r'(?P<pre>\W?)(?P<search>' + main_regex + ')(?P<post>\W?)'

    domain = BooleanField()
    idna = StringField()

    DISPLAY_FIELDS = Observable.DISPLAY_FIELDS + [("domain", "Domain?"), ("idna", "IDNA")]

    @classmethod
    def is_valid(cls, match):
        # Check that the domain is not preceded or followed by a '/'
        # This ensures that we do not match URLs
        if match.group('pre') != '/' and match.group('post') != '/':
            # Check that the domain is valid (by checking TLD)
            value = refang(match.group('search'))
            parts = extract(value)
            if parts.suffix and parts.domain:
                return True

        return False

    def normalize(self):
        self.value = refang(self.value.lower())
        try:
            self.idna = unicode(idna.encode(self.value))
        except idna.core.InvalidCodepoint:
            pass
