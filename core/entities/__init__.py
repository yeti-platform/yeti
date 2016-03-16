KILL_CHAIN_STEPS = (("reconnaisance", "Reconnaissance"),
                    ("weaponisation", "Weaponisation"),
                    ("delivery", "Delivery"),
                    ("exploitation", "Exploitation"),
                    ("installation", "Installation"),
                    ("c2", "C2"),
                    ("objectives", "Objectives"))

from core.entities.entity import Entity
from core.entities.actor import Actor
from core.entities.malware import Malware
from core.entities.exploit import Exploit
from core.entities.exploit_kit import ExploitKit
from core.entities.ttp import TTP
from core.entities.company import Company
