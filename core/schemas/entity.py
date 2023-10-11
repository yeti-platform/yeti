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
    exploit = "exploit"
    identity = "identity"
    intrusion_set = "intrusion-set"
    investigation = "investigation"
    malware = "malware"
    note = "note"
    phone = "phone"
    threat_actor = "threat-actor"
    tool = "tool"


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
    tags: dict[str, TagRelationship] = {}

    @classmethod
    def load(cls, object: dict) -> "EntityTypes":
        if object["type"] in TYPE_MAPPING:
            return TYPE_MAPPING[object["type"]](**object)
        raise ValueError("Attempted to instantiate an undefined entity type.")

    def tag(self, tags: list[str],strict: bool = False,normalize: bool = False) -> "Entity":
        extra_tags = set()
        for tag_name in tags:
            if normalize:
                nfkd_form = unicodedata.normalize("NFKD", tag_name)
                tag_normalized = "".join(
                    [c for c in nfkd_form if not unicodedata.combining(c)]
                )
            else:
                tag_normalized = tag_name

            replacements, _ = Tag.filter({"in__replaces": [tag_normalized]}, count=1)
            tag: Optional[Tag] = None

            if replacements:
                tag = replacements[0]
            # Attempt to find actual tag
            else:
                tag = Tag.find(name=tag_name)
            # Create tag
            if not tag:
                tag = Tag(name=tag_name).save()
            
            tag_link = self.observable_tag(tag.name)
            self.tags[tag.name] = tag_link
            extra_tags |= set(tag.produces)

            extra_tags -= set(tags)
            if extra_tags:
                self.tag(list(extra_tags))

        return self
        
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
    EntityType.attack_pattern: AttackPattern,
    EntityType.campaign: Campaign,
    EntityType.company: Company,
    EntityType.identity: Identity,
    EntityType.intrusion_set: IntrusionSet,
    EntityType.investigation: Investigation,
    EntityType.malware: Malware,
    EntityType.note: Note,
    EntityType.phone: Phone,
    EntityType.threat_actor: ThreatActor,
    EntityType.tool: Tool,
}


REGEXES_ENTITIES = {
    EntityType.exploit: re.compile(
        r"(?P<pre>\W?)(?P<search>CVE-\d{4}-\d{4,7})(?P<post>\W?)"
    )
}


EntityTypes = (
    AttackPattern
    | Campaign
    | Company
    | Identity
    | IntrusionSet
    | Investigation
    | Malware
    | Note
    | Phone
    | ThreatActor
    | Tool
)


EntityClasses = (
    Type[AttackPattern]
    | Type[Campaign]
    | Type[Company]
    | Type[Identity]
    | Type[IntrusionSet]
    | Type[Investigation]
    | Type[Malware]
    | Type[Note]
    | Type[Phone]
    | Type[ThreatActor]
    | Type[Tool]
)
