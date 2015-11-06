import re

from mongoengine import *

from core.observables import Observable
from core.errors import ObservableValidationError


class Hash(Observable):

    family = StringField()

    HASH_LENGTHS = {128: 'md5',
                    160: 'sha1',
                    224: 'sha224',
                    256: 'sha256',
                    384: 'sha384',
                    512: 'sha512',
                    }

    def clean(self):
        h = self.value.lower()
        if not re.match(r'^[a-f0-9]+$', h):
            raise ObservableValidationError("{} is not a valid hex hash".format(self.value))
        self.value = h
        self.family = self.HASH_LENGTHS.get((len(h) / 2) * 8, "Unknown")
