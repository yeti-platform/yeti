from mongoengine import *

from core.entities import Entity
from core.entities import KILL_CHAIN_STEPS

class TTP(Entity):

    killchain = StringField(choices=KILL_CHAIN_STEPS, required=True)
