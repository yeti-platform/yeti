from core.entities.entity import Entity
from core.entities.actor import Actor
from core.entities.malware import Malware
from core.entities.ttp import TTP

KILL_CHAIN_STEPS = ("reconnaisance",
                    "weaponisation",
                    "delivery",
                    "exploitation",
                    "installation",
                    "c2",
                    "objectives")
