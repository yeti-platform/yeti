from __future__ import unicode_literals

import re

from mongoengine import *

from core.observables import Observable

class Email(Observable):

    @staticmethod
    def check_type(txt):
        from core.observables import Hostname
        try:
            localpart, hostname = txt.split("@")
        except Exception:
            return False

        return bool(Hostname.check_type(hostname) and re.match("^[a-zA-Z0-9!#%&'*+-/=?^_`{|}~]+$", localpart))
