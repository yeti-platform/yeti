from mongoengine import *

from core.observables import Observable
from core.observables import Hash


class File(Observable):

    mime_type = StringField(verbose_name="MIME type")
    hashes = ListField(ReferenceField(Hash), verbose_name="Hashes")
    body = FileField(verbose_name="File content")
