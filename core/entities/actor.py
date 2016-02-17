from mongoengine import *
from flask.ext.mongoengine.wtf import model_form

from core.entities import Entity
from core.database import TagListField, StringListField


class Actor(Entity):

    aliases = ListField(StringField(), verbose_name="Aliases")

    @classmethod
    def get_form(klass):
        form = model_form(klass, exclude=klass.exclude_fields)
        form.tags = TagListField("Relevant tags")
        form.aliases = StringListField("Aliases")
        return form

    def add_alias(alias):
        self.modify(add_to_set__aliases=alias)
        self.reload()

    def generate_tags(self):
        return [self.name.lower()]

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ['id', 'name', 'aliases']}
        i['type'] = "Actor"
        return i
