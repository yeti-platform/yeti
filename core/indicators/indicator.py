from mongoengine import *

from core.database import Node, Link
from core.indicators import DIAMOND_EDGES


class Indicator(Node):

    name = StringField(required=True)
    pattern = StringField(required=True)
    diamond = StringField(choices=DIAMOND_EDGES, required=True)
    description = StringField()

    meta = {
        "allow_inheritance": True,
    }

    def __unicode__(self):
        return u"{} (pattern: '{}')".format(self.name, self.pattern)

    @classmethod
    def search(cls, observables):
        for o in observables:
            for i in Indicator.objects():
                if i.match(o):
                    yield o, i

    def match(value):
        raise NotImplementedError("match() method must be implemented in Indicator subclasses")

    def action(self, verb, target, description=None):
        Link.connect(self, target).add_history(verb, description)

    def generate_tags(self):
        return [self.name, self.diamond]

    def info(self):
        return {k: v for k, v in self._data.items() if k in ['name', 'pattern', 'diamond', 'description']}
