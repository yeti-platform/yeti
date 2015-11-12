from mongoengine import *

from core.entities import Entity
from core.entities import KILL_CHAIN_STEPS, DIAMOND_EDGES

class TTP(Entity):

    killchain = StringField(choices=KILL_CHAIN_STEPS)
    dimaond = StringField(choices=DIAMOND_EDGES)
