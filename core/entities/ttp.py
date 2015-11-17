from mongoengine import *

from core.entities import Entity
from core.entities import KILL_CHAIN_STEPS


class TTP(Entity):

    killchain = StringField(choices=KILL_CHAIN_STEPS, required=True)
    description = StringField()

    def info(self):
        return {k: v for k, v in self._data.items() if k in ['name', 'killchain', 'description']}

    def generate_tags(self):
        return [self.name, self.killchain]
