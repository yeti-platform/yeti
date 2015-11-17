from mongoengine import *

from core.entities import Entity

class Actor(Entity):

    aliases = ListField(StringField())

    def add_alias(alias):
        self.modify(add_to_set__aliases=alias)
        self.reload()

    def generate_tags(self):
        return [self.name]
