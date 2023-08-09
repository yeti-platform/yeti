from __future__ import unicode_literals

from mongoengine import *

from core.entities import Entity
from core.database import StringListField


class Actor(Entity):
    aliases = ListField(StringField(), verbose_name="Aliases")

    DISPLAY_FIELDS = Entity.DISPLAY_FIELDS + [("aliases", "Aliases")]

    @classmethod
    def get_form(klass):
        form = Entity.get_form(override=klass)
        form.aliases = StringListField("Aliases")
        return form

    def generate_tags(self):
        return [self.name.lower()]

    def info(self):
        i = Entity.info(self)
        i["aliases"] = self.aliases
        i["type"] = "actor"
        return i
