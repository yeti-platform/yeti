from __future__ import unicode_literals

import re

from mongoengine import *

from core.observables import Observable
from core.errors import ObservableValidationError


class Bitcoin(Observable):

    format = StringField()

    DISPLAY_FIELDS = Observable.DISPLAY_FIELDS + [("format", "Format")]

    @staticmethod
    def check_type(txt):
        if re.match(r'^(1|3)[\w]{25,34}$', txt) and (re.search(
                "[A-Za-z]", txt) and re.search("[0-9]", txt)):
            return True

    def clean(self):
        if not (re.match(r'^(1|3)[\w]{25,34}$', self.value) and
                (re.search("[A-Z]", self.value) and
                 re.search("[0-9]", self.value))):
            raise ObservableValidationError(
                "{} is not a valid Bitcoin address".format(self.value))
        if self.value.startswith("1"):
            self.format = "P2PKH"
        else:
            self.format = "P2SH"
