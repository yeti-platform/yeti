import datetime
from typing import ClassVar

from pydantic import BaseModel, Field

from core import database_arango

DEFAULT_EXPIRATION_DAYS = 30  # Completely arbitrary

def now():
    return datetime.datetime.now(datetime.timezone.utc)

def future():
    return datetime.timedelta(days=DEFAULT_EXPIRATION_DAYS)


class Tag(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: ClassVar[str] = 'tags'
    _type_filter: ClassVar[str | None] = None

    id: str | None = None
    name: str
    count: int = 0
    created: datetime.datetime = Field(default_factory=now)
    default_expiration: datetime.timedelta = Field(default_factory=future)
    produces: list[str] = []
    replaces: list[str] = []

    @classmethod
    def load(cls, object: dict) -> "Tag":
        return cls(**object)

    def absorb(self, other: list[str], permanent: bool) -> int:
        """Absorb other tags into this one."""
        merged = 0
        for tag_name in other:
            old_tag = Tag.find(name=tag_name)
            if old_tag:
                self.count += old_tag.count
                old_tag.count = 0
                if permanent:
                    self.replaces.append(old_tag.name)
                    self.replaces.extend(old_tag.replaces)
                    self.produces.extend(old_tag.produces)
                    old_tag.delete()
                else:
                    old_tag.save()
                merged += 1
            else:
                self.replaces.append(tag_name)

        self.produces = list(set(self.produces) - {self.name})
        self.replaces = list(set(self.replaces) - {self.name})
        self.save()
        return merged
