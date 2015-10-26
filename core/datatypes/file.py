import re

from mongoengine import *

from core.datatypes import Element


class File(Element):

    mime_type = StringField()
    hashes = ListField(EmbeddedDocumentField(Tag))

    def clean(self):
        h = self.value.lower()
        if not re.match(r'^[a-f0-9]+$', h):
            raise ValidationError("{} is not a valid hex hash".format(self.value))
        self.value = h
        self.type = self.HASH_LENGTHS.get((len(h) / 2) * 8, "Unknown")
