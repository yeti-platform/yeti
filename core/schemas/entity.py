import datetime
from enum import Enum

import re
from typing import Type

from pydantic import BaseModel, Field
from core import database_arango
import re


def now():
    return datetime.datetime.now(datetime.timezone.utc)


class EntityType(str, Enum):
    threat_actor = "threat-actor"
    intrusion_set = "intrusion-set"
    tool = "tool"
    malware = "malware"
    campaign = "campaign"
    attack_pattern = "attack-pattern"
    identity = "identity"
    exploit = "exploit"
    company = "company"


class Entity(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: str = "entities"
    _type_filter: str = ""

    root_type: str = Field("entity", const=True)
    id: str | None = None
    type: str
    name: str
    description: str = ""
    created: datetime.datetime = Field(default_factory=now)
    modified: datetime.datetime = Field(default_factory=now)
    relevant_tags: list[str] = []

    @classmethod
    def load(cls, object: dict) -> "EntityTypes":
        if object["type"] in TYPE_MAPPING:
            return TYPE_MAPPING[object["type"]](**object)
        raise ValueError("Attempted to instantiate an undefined entity type.")

class Company(Entity):
    
    _type:str = EntityType.company
    _type_filter:str = EntityType.company

class ThreatActor(Entity):
    _type_filter: str = "threat-actor"
    type: str = Field("threat-actor", const=True)

    aliases: list[str] = []


class IntrusionSet(Entity):
    _type_filter: str = "intrusion-set"
    type: str = Field("intrusion-set", const=True)

    aliases: list[str] = []
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)


class Tool(Entity):
    _type_filter: str = "tool"
    type: str = Field("tool", const=True)

    kill_chain_phases: list[str] = []
    tool_version: str = ""


class AttackPattern(Entity):
    _type_filter: str = "attack-pattern"
    type: str = Field("attack-pattern", const=True)

    kill_chain_phases: list[str] = []


class Malware(Entity):
    _type_filter: str = "malware"
    type: str = Field("malware", const=True)

    kill_chain_phases: list[str] = []
    aliases: list[str] = []
    family: str = ""


class Campaign(Entity):
    _type_filter: str = "campaign"
    type: str = Field("campaign", const=True)

    aliases: list[str] = []
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)


class Identity(Entity):
    _type_filter: str = "identity"
    type: str = Field("identity", const=True)

    identity_class: list[str] = []
    sectors: list[str] = []
    contact_information: str = ""


TYPE_MAPPING: dict[str, "EntityClasses"] = {
    "threat-actor": ThreatActor,
    "intrusion-set": IntrusionSet,
    "tool": Tool,
    "attack-pattern": AttackPattern,
    "malware": Malware,
    "campaign": Campaign,
    "entities": Entity,
    "entity": Entity,
    "compagny": Com
}
REGEXES_ENTITIES = {
    EntityType.exploit: re.compile(
        r"(?P<pre>\W?)(?P<search>CVE-\d{4}-\d{4,7})(?P<post>\W?)"
    )
}
REGEXES_ENTITIES = [
    (EntityType.exploit, re.compile(r"(?P<pre>\W?)(?P<search>CVE-\d{4}-\d{4,7})(?P<post>\W?)")),
]
EntityTypes = ThreatActor | IntrusionSet | Tool | Malware | Campaign | AttackPattern
EntityClasses = (
    Type[ThreatActor]
    | Type[IntrusionSet]
    | Type[Tool]
    | Type[Malware]
    | Type[Campaign]
    | Type[AttackPattern]
)
