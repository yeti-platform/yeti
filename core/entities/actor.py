from mongoengine import *

from core.entities import Entity

class Actor(Entity):

    aliases = ListField(StringField(), verbose_name="Actor")

    def add_alias(alias):
        self.modify(add_to_set__aliases=alias)
        self.reload()

    def generate_tags(self):
        return [self.name.lower()]

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ['id', 'name', 'aliases']}
        i['type'] = "Actor"
        return i
