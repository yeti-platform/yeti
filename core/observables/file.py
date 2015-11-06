from mongoengine import *

from core.observables import Observable
from core.observables import Hash


class File(Observable):

    mime_type = StringField()
    hashes = ListField(ReferenceField(Hash))
    body = FileField()
