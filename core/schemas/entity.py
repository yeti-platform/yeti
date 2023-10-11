import datetime
import re
from enum import Enum
from typing import ClassVar, Literal, Type

from pydantic import BaseModel, Field

from core import database_arango
from core.helpers import now


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
    investigation = "investigation"


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
    type: Literal[EntityType.note] = EntityType.note
    _type_filter: ClassVar[str] = EntityType.note


class Phone(Entity):
    _type_filter: ClassVar[str] = EntityType.phone
    type: Literal[EntityType.phone] = EntityType.phone


class Company(Entity):
    type: Literal[EntityType.company] = EntityType.company
    _type_filter: ClassVar[str] = EntityType.company


class ThreatActor(Entity):
    _type_filter: ClassVar[str] = EntityType.threat_actor
    type: Literal[EntityType.threat_actor] = EntityType.threat_actor

    aliases: list[str] = []


class IntrusionSet(Entity):
    _type_filter: ClassVar[str] = EntityType.intrusion_set
    type: Literal[EntityType.intrusion_set] = EntityType.intrusion_set

    aliases: list[str] = []
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)


class Tool(Entity):
    _type_filter: ClassVar[str] = EntityType.tool
    type: Literal[EntityType.tool] = EntityType.tool

    kill_chain_phases: list[str] = []
    tool_version: str = ""


class AttackPattern(Entity):
    _type_filter: ClassVar[str] = EntityType.attack_pattern
    type: Literal[EntityType.attack_pattern] = EntityType.attack_pattern

    kill_chain_phases: list[str] = []


class Malware(Entity):
    _type_filter: ClassVar[str] = EntityType.malware
    type: Literal[EntityType.malware] = EntityType.malware

    kill_chain_phases: list[str] = []
    aliases: list[str] = []
    family: str = ""


class Campaign(Entity):
    _type_filter: ClassVar[str] = EntityType.campaign
    type: Literal[EntityType.campaign] = EntityType.campaign

    aliases: list[str] = []
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)


class Identity(Entity):
    _type_filter: ClassVar[str] = EntityType.identity
    type: Literal[EntityType.identity] = EntityType.identity

    identity_class: list[str] = []
    sectors: list[str] = []
    contact_information: str = ""


class Investigation(Entity):
    _type_filter: ClassVar[str] = EntityType.investigation
    type: Literal[EntityType.investigation] = EntityType.investigation

    reference: str = ""


TYPE_MAPPING = {
    'entities': Entity,
    'entity': Entity,
    EntityType.threat_actor: ThreatActor,
    EntityType.intrusion_set: IntrusionSet,
    EntityType.tool: Tool,
    EntityType.attack_pattern: AttackPattern,
    EntityType.malware: Malware,
    EntityType.campaign: Campaign,
    EntityType.company: Company,
    EntityType.phone: Phone,
    EntityType.note: Note,
    EntityType.identity: Identity,
    EntityType.investigation: Investigation,
}


REGEXES_ENTITIES = {
    EntityType.exploit: re.compile(
        r"(?P<pre>\W?)(?P<search>CVE-\d{4}-\d{4,7})(?P<post>\W?)"
    )
}


EntityTypes = (
    ThreatActor
    | IntrusionSet
    | Tool
    | Malware
    | Campaign
    | AttackPattern
    | Identity
    | Company
    | Phone
    | Note
    | Investigation
)


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
    | Type[Investigation]
)
