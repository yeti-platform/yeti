from mongoengine import *

from core.database import Node

class Indicator(Node):

    name = StringField(required=True)
    pattern = StringField(required=True)
    description = StringField()

    meta = {
        "allow_inheritance": True,
    }

    def __unicode__(self):
        return u"{} (pattern: '{}')".format(self.name, self.pattern)

    def match(value):
        raise NotImplementedError("match() method must be implemented in Indicator subclasses")
