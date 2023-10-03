import datetime
import re
from enum import Enum
from typing import ClassVar, Literal, Type

from pydantic import BaseModel, Field

from core import database_arango


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
    phone = "phone"
    note = "note"

class Entity(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: ClassVar[str] = "entities"
    _type_filter: ClassVar[str] = ""

    root_type: Literal["entity"] = "entity"
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
class Note(Entity):
    type:str = EntityType.note
    _type_filter:str = EntityType.note

class Phone(Entity):
    type:str = EntityType.phone
    _type_filter:str = EntityType.phone

class Company(Entity):
    
    type:str = EntityType.company
    _type_filter:str = EntityType.company

class ThreatActor(Entity):
    _type_filter: ClassVar[str] = EntityType.threat_actor
    type: Literal["threat-actor"] = EntityType.threat_actor

    aliases: list[str] = []


class IntrusionSet(Entity):
    _type_filter: ClassVar[str] = EntityType.intrusion_set
    type: Literal["intrusion-set"] = EntityType.intrusion_set

    aliases: list[str] = []
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)


class Tool(Entity):
    _type_filter: ClassVar[str] = EntityType.tool
    type: Literal["tool"] = EntityType.tool

    kill_chain_phases: list[str] = []
    tool_version: str = ""


class AttackPattern(Entity):
    _type_filter: ClassVar[str] = EntityType.attack_pattern
    type: Literal["attack-pattern"] = EntityType.attack_pattern

    kill_chain_phases: list[str] = []


class Malware(Entity):
    _type_filter: ClassVar[str] = EntityType.malware
    type: Literal["malware"] = EntityType.malware

    kill_chain_phases: list[str] = []
    aliases: list[str] = []
    family: str = ""


class Campaign(Entity):
    _type_filter: ClassVar[str] = EntityType.campaign
    type: Literal["campaign"] = EntityType.campaign

    aliases: list[str] = []
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)


class Identity(Entity):
    _type_filter: ClassVar[str] = EntityType.identity
    type: Literal["identity"] = EntityType.identity

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
    "compagny": Company,
    "phone": Phone,
    "note": Note,
}
REGEXES_ENTITIES = {
    EntityType.exploit: re.compile(
        r"(?P<pre>\W?)(?P<search>CVE-\d{4}-\d{4,7})(?P<post>\W?)"
    )
}
REGEXES_ENTITIES = [
    (EntityType.exploit, re.compile(r"(?P<pre>\W?)(?P<search>CVE-\d{4}-\d{4,7})(?P<post>\W?)")),
]
EntityTypes = ThreatActor | IntrusionSet | Tool | Malware | Campaign | AttackPattern | Identity | Company | Phone | Note
EntityClasses = (
    Type[ThreatActor]
    | Type[IntrusionSet]
    | Type[Tool]
    | Type[Malware]
    | Type[Campaign]
    | Type[AttackPattern]
    | Type[Identity]
    | Type[Company]
    | Type[Phone]
    | Type[Note]
)
