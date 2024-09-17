import datetime
from typing import ClassVar

from pydantic import Field

from core.helpers import now
from core.schemas import entity


class ThreatActor(entity.Entity):
    _type_filter: ClassVar[str] = entity.EntityType.threat_actor
    type: entity.EntityType = entity.EntityType.threat_actor

    threat_actor_types: list[str] = []
    aliases: list[str] = []
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)
