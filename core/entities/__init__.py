KILL_CHAIN_STEPS = (("reconnaisance", "Reconnaissance"),
                    ("weaponisation", "Weaponisation"),
                    ("delivery", "Delivery"),
                    ("exploitation", "Exploitation"),
                    ("installation", "Installation"),
                    ("c2", "C2"),
                    ("objectives", "Act on objectives"),
                   )

DIAMOND_EDGES = ("Target", "Actor", "Infrastructure", "Capability")

from core.entities.entity import Entity
from core.entities.actor import Actor
from core.entities.malware import Malware
from core.entities.ttp import TTP
