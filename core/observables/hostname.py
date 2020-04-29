from __future__ import unicode_literals

import idna
from mongoengine import BooleanField, StringField
from core.common.utils import tldextract_parser

from core.errors import ObservableValidationError
from core.observables import Observable
from core.helpers import refang

class Hostname(Observable):

    main_regex = r'[-.\w[\]]+\[?\.\]?[\w-]+'
    regex = r'(?P<pre>\W?)(?P<search>' + main_regex + ')(?P<post>\W?)'

    domain = BooleanField()
    idna = StringField()

    DISPLAY_FIELDS = Observable.DISPLAY_FIELDS + [("domain", "Domain?"),
                                                  ("idna", "IDNA")]

    @classmethod
    def is_valid(cls, match):
        # Check that the domain is not preceded or followed by a '/'
        # This ensures that we do not match URLs
        if match.group('pre') != '/' and match.group('post') != '/':
            # Check that the domain is valid (by checking TLD)
            value = refang(match.group('search'))

            if len(value) <= 255:
                parts = tldextract_parser(value)
                if parts.suffix and parts.domain:
                    return True

        return False

    def normalize(self):
        self.value = refang(self.value.lower())
        # Remove trailing dot if existing
        if self.value.endswith("."):
            self.value = self.value[:-1]
        try:
            self.idna = self.value
        except idna.core.InvalidCodepoint:
            pass
        except Exception as e:
            raise ObservableValidationError(e.with_traceback())
