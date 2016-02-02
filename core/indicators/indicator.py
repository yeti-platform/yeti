from mongoengine import *

from core.database import Node, Link
from core.indicators import DIAMOND_EDGES


class Indicator(Node):

    name = StringField(required=True, max_length=1024, verbose_name="Name")
    pattern = StringField(required=True, verbose_name="Pattern")
    location = StringField(required=True, max_length=255, verbose_name="Location")
    diamond = StringField(choices=DIAMOND_EDGES, required=True, verbose_name="Diamond Edge")
    description = StringField(verbose_name="Description")

    meta = {
        "allow_inheritance": True,
    }

    def __unicode__(self):
        return u"{} (pattern: '{}')".format(self.name, self.pattern)

    @classmethod
    def search(cls, observables):
        for o in observables:
            for i in Indicator.objects():
                print i
                if i.match(o):
                    yield o, i

    def match(self, value):
        raise NotImplementedError("match() method must be implemented in Indicator subclasses")

    def action(self, verb, target, description=None):
        Link.connect(self, target).add_history(verb, description)

    def generate_tags(self):
        return [self.diamond.lower()]

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ['name', 'pattern', 'diamond', 'description', 'location']}
        i['id'] = str(self.id)
        i['type'] = self.type
        return i
