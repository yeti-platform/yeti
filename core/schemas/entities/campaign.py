import datetime
from typing import ClassVar, Literal

from pydantic import Field

from core.helpers import now
from core.schemas import entity


class Campaign(entity.Entity):
    _type_filter: ClassVar[str] = "campaign"
    type: Literal["campaign"] = "campaign"

    aliases: list[str] = []
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)
