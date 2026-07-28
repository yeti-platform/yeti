import datetime
import logging
from typing import ClassVar, Literal

from pydantic import ConfigDict, Field, computed_field

from core import database_arango
from core.config.config import yeti_config
from core.events import message
from core.events.producer import producer
from core.helpers import now
from core.schemas.model import YetiModel

DEFAULT_EXPIRATION = datetime.timedelta(
    days=yeti_config.get(
        "tag",
        "default_tag_expiration",
        default=90,  # Completely arbitrary
    )
)

MAX_TAG_LENGTH = 250
MAX_TAGS_REQUEST = 50


def future():
    return DEFAULT_EXPIRATION


class Tag(YetiModel, database_arango.ArangoYetiConnector):
    model_config = ConfigDict(str_strip_whitespace=True)

    _collection_name: ClassVar[str] = "tags"
    _root_type: Literal["tag"] = "tag"
    _type_filter: ClassVar[str | None] = None

    name: str = Field(max_length=MAX_TAG_LENGTH)
    description: str | None = None

    count: int = 0
    created: datetime.datetime = Field(default_factory=now)
    default_expiration: datetime.timedelta = DEFAULT_EXPIRATION
    produces: list[str] = []
    replaces: list[str] = []

    @computed_field(return_type=Literal["tag"])
    @property
    def root_type(self):
        return self._root_type

    @classmethod
    def load(cls, object: dict) -> "Tag":
        return cls(**object)

    def increment_count(self, delta: int) -> None:
        """Atomically adjust this tag's persisted count by `delta` and update
        this in-memory instance to match.

        Unlike `self.count += delta; self.save()`, this is safe under
        concurrent callers tagging/untagging with the same tag -- see
        link_to()'s docstring in database_arango.py for why a full-document
        read-modify-write save() isn't.
        """
        aql = """
        FOR t IN tags FILTER t._key == @key
        UPDATE t WITH { count: t.count + @delta } IN tags
        RETURN NEW.count
        """
        result = list(
            database_arango.execute_aql_with_conflict_retry(
                self._db, aql, {"key": self.id, "delta": delta}
            )
        )
        self.count = result[0]
        try:
            producer.publish_event(
                message.ObjectEvent(type=message.EventType.update, yeti_object=self)
            )
        except Exception:
            logging.exception("Error while publishing event")

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
