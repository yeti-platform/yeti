from __future__ import unicode_literals

from mongoengine import *
from flask_mongoengine.wtf import model_form
from flask import url_for

from core.database import Node
from core.indicators import DIAMOND_EDGES
from core.database import Node, EntityListField

class Indicator(Node):

    DISPLAY_FIELDS = [("name", "Name"), ("pattern", "Pattern"), ("location", "Location"), ("diamond", "Diamond")]

    name = StringField(required=True, max_length=1024, verbose_name="Name")
    pattern = StringField(required=True, verbose_name="Pattern")
    location = StringField(required=True, max_length=255, verbose_name="Location")
    diamond = StringField(choices=DIAMOND_EDGES, required=True, verbose_name="Diamond Edge")
    description = StringField(verbose_name="Description")

    meta = {
        "allow_inheritance": True,
        "ordering": ["name"],
    }

    @classmethod
    def get_form(klass):
        form = model_form(klass, exclude=klass.exclude_fields)
        form.links = EntityListField("Link with entities")
        return form

    def __unicode__(self):
        return u"{} (pattern: '{}')".format(self.name, self.pattern)

    @classmethod
    def search(cls, observables):
        indicators = list(Indicator.objects())
        for o in observables:
            for i in indicators:
                if i.match(o):
                    yield o, i

    def match(self, value):
        raise NotImplementedError("match() method must be implemented in Indicator subclasses")

    def action(self, target, source, verb="Indicates"):
        self.active_link_to(target, verb, source)

    def generate_tags(self):
        return [self.diamond.lower(), self.name.lower()]

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ['name', 'pattern', 'diamond', 'description', 'location']}
        i['id'] = str(self.id)
        i['url'] = url_for("api.Indicator:post", id=str(self.id), _external=True)
        i['human_url'] = url_for("frontend.IndicatorView:get", id=str(self.id), _external=True)
        i['type'] = self.type
        return i
