from datetime import datetime

from mongoengine import *

from core.database import Node, Link


class Entity(Node):

    name = StringField(required=True, sparse=True)
    description = StringField()

    meta = {
        "allow_inheritance": True,
    }

    def __unicode__(self):
        return u"{}".format(self.name)

    def action(self, verb, target, description=None):
        Link.connect(self, target).add_history(verb, description)
