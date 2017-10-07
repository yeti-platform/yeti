from __future__ import unicode_literals

from mongoengine import StringField

from core.observables import Observable


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

    DISPLAY_FIELDS = Observable.DISPLAY_FIELDS + [("family", "Family")]

    regex = r'(?P<search>[a-fA-F0-9]+)'

    @classmethod
    def is_valid(cls, match):
        return (len(match.group('search')) / 2 * 8) in Hash.HASH_LENGTHS

    def normalize(self):
        self.value = self.value.lower()
        self.family = self.HASH_LENGTHS.get((len(self.value) / 2) * 8)
