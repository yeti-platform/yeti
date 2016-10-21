from __future__ import unicode_literals

import re

from mongoengine import *

from core.observables import Observable
from core.errors import ObservableValidationError


class Hash(Observable):

    family = StringField()

    HASH_LENGTHS = {
        128: 'md5',
        160: 'sha1',
        224: 'sha224',
        256: 'sha256',
        384: 'sha384',
        512: 'sha512',
    }

    @staticmethod
    def check_type(txt):
        if re.match(r'^[a-f0-9]+$', txt.lower()):
            return True

    def clean(self):
        h = self.value.lower()
        if not re.match(r'^[a-f0-9]+$', h):
            raise ObservableValidationError("{} is not a valid hex hash".format(self.value))
        self.family = self.HASH_LENGTHS.get((len(h) / 2) * 8)
        if self.family is None:
            raise ObservableValidationError("{} is not a valid hash (md5, sha1, sha224, sha256, sha384, sha512)".format(self.value))
        self.value = h
