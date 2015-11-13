from datetime import datetime

from mongoengine import *

from core.database import Node


class Entity(Node):

    name = StringField(required=True, unique=True, sparse=True)
    description = StringField()

    meta = {
        "allow_inheritance": True,
    }

    def __unicode__(self):
        return u"{}".format(self.name)
