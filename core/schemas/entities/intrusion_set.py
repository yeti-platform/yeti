import datetime
from typing import ClassVar

from pydantic import Field

from core.helpers import now
from core.schemas import entity


class IntrusionSet(entity.Entity):
    _type_filter: ClassVar[str] = entity.EntityType.intrusion_set
    type: entity.EntityType = entity.EntityType.intrusion_set

    aliases: list[str] = []
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)
