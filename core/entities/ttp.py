from mongoengine import *

from core.entities import Entity
from core.entities import KILL_CHAIN_STEPS


class TTP(Entity):

    killchain = StringField(choices=KILL_CHAIN_STEPS, required=True)
    description = StringField()

    def info(self):
        i = {k: v for k, v in self._data.items() if k in ['name', 'killchain', 'description']}
        i['id'] = str(self.id)
        i['type'] = 'TTP'
        return i

    def generate_tags(self):
        return [self.killchain.lower()]
