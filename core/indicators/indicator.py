from mongoengine import *

class Indicator(Document):

    name = StringField(required=True, unique=True)
    pattern = StringField(required=True)
    description = StringField()

    meta = {"allow_inheritance": True}

    def match(value):
        raise NotImplementedError("match() method must be implemented in Indicator subclasses")
