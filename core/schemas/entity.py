import datetime
import re
from enum import Enum
from typing import ClassVar, Literal, Optional, Type
import unicodedata

from pydantic import BaseModel, Field

from core import database_arango
from core.helpers import now
from core.schemas.graph import TagRelationship
from core.schemas.tag import Tag

class EntityType(str, Enum):
    attack_pattern = "attack-pattern"
    campaign = "campaign"
    company = "company"
    identity = "identity"
    intrusion_set = "intrusion-set"
    investigation = "investigation"
    malware = "malware"
    note = "note"
    phone = "phone"
    threat_actor = "threat-actor"
    tool = "tool"
    vulnerability = "vulnerability"
    course_of_action = "course-of-action"


class Entity(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: ClassVar[str] = "entities"
    _type_filter: ClassVar[str] = ""

    root_type: Literal["entity"] = "entity"
    id: str | None = None
    type: str
    name: str = Field(min_length=1)
    description: str = ""
    created: datetime.datetime = Field(default_factory=now)
    modified: datetime.datetime = Field(default_factory=now)
    tags: dict[str, TagRelationship] = {}

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

    threat_actor_types: list[str] = []
    aliases: list[str] = []
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)


class IntrusionSet(Entity):
    _type_filter: ClassVar[str] = EntityType.intrusion_set
    type: Literal[EntityType.intrusion_set] = EntityType.intrusion_set

    aliases: list[str] = []
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)


class Tool(Entity):
    _type_filter: ClassVar[str] = EntityType.tool
    type: Literal[EntityType.tool] = EntityType.tool

    aliases: list[str] = []
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

    identity_class: str = ""
    sectors: list[str] = []
    contact_information: str = ""


class Investigation(Entity):
    _type_filter: ClassVar[str] = EntityType.investigation
    type: Literal[EntityType.investigation] = EntityType.investigation

    reference: str = ""


class Vulnerability(Entity):
    _type_filter: ClassVar[str] = EntityType.vulnerability
    type: Literal[EntityType.vulnerability] = EntityType.vulnerability

    reference: str = ""


class CourseOfAction(Entity):
    _type_filter: ClassVar[str] = EntityType.course_of_action
    type: Literal[EntityType.course_of_action] = EntityType.course_of_action


TYPE_MAPPING = {
    'entities': Entity,
    'entity': Entity,
    EntityType.attack_pattern: AttackPattern,
    EntityType.campaign: Campaign,
    EntityType.company: Company,
    EntityType.course_of_action: CourseOfAction,
    EntityType.identity: Identity,
    EntityType.intrusion_set: IntrusionSet,
    EntityType.investigation: Investigation,
    EntityType.malware: Malware,
    EntityType.note: Note,
    EntityType.phone: Phone,
    EntityType.threat_actor: ThreatActor,
    EntityType.tool: Tool,
    EntityType.vulnerability: Vulnerability,
}


REGEXES_ENTITIES = {
    EntityType.vulnerability: re.compile(
        r"(?P<pre>\W?)(?P<search>CVE-\d{4}-\d{4,7})(?P<post>\W?)"
    )
}


EntityTypes = (
    AttackPattern
    | Campaign
    | Company
    | CourseOfAction
    | Identity
    | IntrusionSet
    | Investigation
    | Malware
    | Note
    | Phone
    | ThreatActor
    | Tool
    | Vulnerability
)


EntityClasses = (
    Type[AttackPattern]
    | Type[Campaign]
    | Type[Company]
    | Type[CourseOfAction]
    | Type[Identity]
    | Type[IntrusionSet]
    | Type[Investigation]
    | Type[Malware]
    | Type[Note]
    | Type[Phone]
    | Type[ThreatActor]
    | Type[Tool]
    | Type[Vulnerability]
)
