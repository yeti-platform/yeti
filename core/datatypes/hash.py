import re

from mongoengine import *

from core.datatypes import Element


class Hash(Element):

    type = StringField()

    HASH_LENGTHS = {128: 'MD5',
                    160: 'SHA1',
                    224: 'SHA-224',
                    256: 'SHA-256',
                    384: 'SHA-384',
                    512: 'SHA-512',
                    }

    def clean(self):
        h = self.value.lower()
        if not re.match(r'^[a-f0-9]+$', h):
            raise ValidationError("{} is not a valid hex hash".format(self.value))
        self.value = h
        self.type = self.HASH_LENGTHS.get((len(h) / 2) * 8, "Unknown")
