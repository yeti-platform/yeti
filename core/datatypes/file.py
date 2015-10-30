import re
import hashlib

from mongoengine import *

from core.datatypes import Element
from core.datatypes import Hash

HASH_TYPES_DICT = {'md5': hashlib.md5,
                   'sha1': hashlib.sha1,
                   'sha256': hashlib.sha256,
                   'sha512': hashlib.sha512}

class File(Element):

    mime_type = StringField()
    hashes = ListField(ReferenceField(Hash))
    body = FileField()
    filenames = ListField(StringField())

    def clean(self):
        # try:
        self.update(add_to_set__filenames=self.value)
        # except errors.OperationError as e:
        #     self.filenames.append(self.value)


        hashes = self.add_hashes()
        # try:
        for h in hashes:
            self.update(add_to_set__hashes=Hash.get_or_create(h.hexdigest()))
        # except errors.OperationError as e:
        #     self.hashes = [Hash.get_or_create(h.hexdigest()) for h in hashes]

        # get filetype


    def add_hashes(self):
        hashes = []
        f = self.body
        hashers = {k: HASH_TYPES_DICT[k]() for k in HASH_TYPES_DICT}

        while True:
            chunk = f.read(512*16)
            if not chunk:
                break
            for h in hashers.itervalues():
                h.update(chunk)

        return hashers.values()
