from __future__ import unicode_literals

from core.observables import Observable, Hostname
from core.helpers import refang


class Email(Observable):
    regex = (
        r"(?P<search>[-.+\w!#%&'*/=?^_`{|}~]+@(?P<domain>" + Hostname.main_regex + "))"
    )

    @classmethod
    def is_valid(cls, match):
        return Hostname.check_type(match.group("domain"))

    def normalize(self):
        self.value = refang(self.value.lower())
