import re
import hashlib

from mongoengine import *
from mongoengine import errors as MongoErrors

from core.observables import Observable
from core.observables import Hash

class File(Observable):

    mime_type = StringField()
    hashes = ListField(ReferenceField(Hash))
    body = FileField()
