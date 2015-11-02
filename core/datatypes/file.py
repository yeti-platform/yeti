import re
import hashlib

from mongoengine import *
from mongoengine import errors as MongoErrors

from core.datatypes import Element
from core.datatypes import Hash

class File(Element):

    mime_type = StringField()
    hashes = ListField(ReferenceField(Hash))
    body = FileField()
