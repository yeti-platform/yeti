import datetime
from typing import ClassVar, Literal

from pydantic import Field

from core.helpers import now
from core.schemas import entity


class ThreatActor(entity.Entity):
    _type_filter: ClassVar[str] = entity.EntityType.threat_actor
    type: Literal[entity.EntityType.threat_actor] = entity.EntityType.threat_actor

    threat_actor_types: list[str] = []
    aliases: list[str] = []
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)
