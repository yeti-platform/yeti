from __future__ import unicode_literals

from mongoengine import *

from core.observables import Observable
from core.observables import Hash


class File(Observable):

    value = StringField(verbose_name="SHA256 hash")

    mime_type = StringField(verbose_name="MIME type")
    hashes = ListField(ReferenceField(Hash), verbose_name="Hashes")
    body = ReferenceField("AttachedFile")
    filenames = ListField(StringField(), verbose_name="Filenames")

    DISPLAY_FIELDS = Observable.DISPLAY_FIELDS + [("mime_type", "MIME Type")]

    @staticmethod
    def check_type(txt):
        return True
