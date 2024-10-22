import datetime
from typing import ClassVar, Literal

from pydantic import Field

from core.helpers import now
from core.schemas import entity


class IntrusionSet(entity.Entity):
    _type_filter: ClassVar[str] = entity.EntityType.intrusion_set
    type: Literal[entity.EntityType.intrusion_set] = entity.EntityType.intrusion_set

    aliases: list[str] = []
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)
