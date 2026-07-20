from __future__ import annotations

import datetime
from enum import Enum
from typing import TYPE_CHECKING, ClassVar, List, Literal, Self, Union, cast

from pydantic import ConfigDict, Field, computed_field

from core import database_arango
from core.helpers import now
from core.schemas.model import YetiAclModel, YetiContextModel, YetiTagModel

# EntityType, EntityTypes and TYPE_MAPPING are defined statically at the bottom
# of this module (see "Static type registry"). TYPE_MAPPING must exist before
# the functions below are *called*, which is always the case at runtime.
TYPE_MAPPING: dict[str, type["Entity"]] = {}


class Entity(
    YetiTagModel, YetiAclModel, YetiContextModel, database_arango.ArangoYetiConnector
):
    model_config = ConfigDict(str_strip_whitespace=True)
    _exclude_overwrite: list[str] = ["related_observables_count"]
    _collection_name: ClassVar[str] = "entities"
    _type_filter: ClassVar[str] = ""
    _root_type: Literal["entity"] = "entity"

    if TYPE_CHECKING:
        # Each concrete entity subclass declares `type` as its own
        # Literal[EntityType.*] field. Declared here as a property
        # (type-check time only, so not a required field) so code holding a
        # base Entity can resolve `.type`.
        @property
        def type(self) -> "EntityType": ...

    name: str = Field(min_length=1)
    description: str = ""
    created: datetime.datetime = Field(default_factory=now)
    modified: datetime.datetime = Field(default_factory=now)

    @computed_field(return_type=Literal["entity"])
    @property
    def root_type(self):
        return self._root_type

    @classmethod
    def load(cls, object: dict) -> "EntityTypes":
        if cls._type_filter:
            loader = TYPE_MAPPING[cls._type_filter]
        elif object["type"] in TYPE_MAPPING:
            loader = TYPE_MAPPING[object["type"]]
        else:
            raise ValueError("Attempted to instantiate an undefined entity type.")
        # loader is a TYPE_MAPPING value (type[Entity] statically); every
        # concrete member is one of the enumerated EntityTypes (or a private/
        # subtype covered by EntityTypesRuntime, not this static union).
        return cast("EntityTypes", loader(**object))

    def save(self, *args, **kwargs) -> "Self":
        self.modified = now()
        return super().save(*args, **kwargs)

    @classmethod
    def is_valid(cls, object: "Entity") -> bool:
        return False


def create(*, name: str, type: str, **kwargs) -> "EntityTypes":
    """
    Create an entity of the given type without saving it to the database.

    type is a string representing the type of entity to create.
    If the type is not valid, a ValueError is raised.

    kwargs must contain "name" fields and will be handled by
    pydantic.
    """
    if type not in TYPE_MAPPING:
        raise ValueError(f"{type} is not a valid entity type")
    return cast("EntityTypes", TYPE_MAPPING[type](name=name, **kwargs))


def save(*, name: str, type: str, tags: List[str] | None = None, **kwargs):
    indicator_obj = create(name=name, type=type, **kwargs).save()
    if tags:
        indicator_obj.tag(tags)
    return indicator_obj


def find(*, name: str, **kwargs) -> "EntityTypes | None":
    return cast("EntityTypes | None", Entity.find(name=name, **kwargs))


# ---------------------------------------------------------------------------
# Static type registry (see observable.py for the rationale).
# ---------------------------------------------------------------------------
from core.schemas.entities.attack_pattern import AttackPattern  # noqa: E402
from core.schemas.entities.campaign import Campaign  # noqa: E402
from core.schemas.entities.company import Company  # noqa: E402
from core.schemas.entities.course_of_action import CourseOfAction  # noqa: E402
from core.schemas.entities.identity import Identity  # noqa: E402
from core.schemas.entities.intrusion_set import IntrusionSet  # noqa: E402
from core.schemas.entities.investigation import Investigation  # noqa: E402
from core.schemas.entities.malware import Malware  # noqa: E402
from core.schemas.entities.note import Note  # noqa: E402
from core.schemas.entities.phone import Phone  # noqa: E402
from core.schemas.entities.threat_actor import ThreatActor  # noqa: E402
from core.schemas.entities.tool import Tool  # noqa: E402
from core.schemas.entities.vulnerability import Vulnerability  # noqa: E402
from core.schemas.loader import load_private_types  # noqa: E402


class EntityType(str, Enum):
    # Member names must be valid identifiers, so the four hyphenated types use
    # underscores here; the *values* keep the wire-format hyphens.
    attack_pattern = "attack-pattern"
    campaign = "campaign"
    company = "company"
    course_of_action = "course-of-action"
    identity = "identity"
    intrusion_set = "intrusion-set"
    investigation = "investigation"
    malware = "malware"
    note = "note"
    phone = "phone"
    threat_actor = "threat-actor"
    tool = "tool"
    vulnerability = "vulnerability"


_ENTITY_CLASSES: list[type[Entity]] = [
    AttackPattern,
    Campaign,
    Company,
    CourseOfAction,
    Identity,
    IntrusionSet,
    Investigation,
    Malware,
    Note,
    Phone,
    ThreatActor,
    Tool,
    Vulnerability,
]

_private_entity_classes = load_private_types("core.schemas.entities", Entity)

TYPE_MAPPING = {"entity": Entity, "entities": Entity}
for _cls in (*_ENTITY_CLASSES, *_private_entity_classes):
    TYPE_MAPPING[str(_cls.model_fields["type"].default)] = _cls

EntityTypes = Union[
    AttackPattern,
    Campaign,
    Company,
    CourseOfAction,
    Identity,
    IntrusionSet,
    Investigation,
    Malware,
    Note,
    Phone,
    ThreatActor,
    Tool,
    Vulnerability,
]
# Separate runtime-widened symbol so type checkers keep full checking on the
# static EntityTypes above (see observable.py for the rationale). Internal code
# annotates EntityTypes; FastAPI request/response models annotate
# EntityTypesRuntime.
EntityTypesRuntime = EntityTypes
if _private_entity_classes:
    EntityTypesRuntime = Union[(EntityTypes, *_private_entity_classes)]
