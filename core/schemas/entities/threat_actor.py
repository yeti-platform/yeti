import datetime
from typing import ClassVar, Literal

from pydantic import Field

from core.helpers import now
from core.schemas import entity


class ThreatActor(entity.Entity):
    _type_filter: ClassVar[str] = "threat-actor"
    type: Literal["threat-actor"] = "threat-actor"

    threat_actor_types: list[str] = []
    aliases: list[str] = []
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)
