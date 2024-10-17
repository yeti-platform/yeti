import datetime
import re
import unicodedata
from typing import ClassVar, Literal

from pydantic import Field, computed_field

from core import database_arango
from core.config.config import yeti_config
from core.helpers import now
from core.schemas.model import YetiModel

DEFAULT_EXPIRATION = datetime.timedelta(
    days=yeti_config.get(
        "tag",
        "default_tag_expiration",
        default=90,  # Completely arbitrary
    )
)

MAX_TAG_LENGTH = 50
MAX_TAGS_REQUEST = 50


def future():
    return DEFAULT_EXPIRATION


def normalize_name(tag_name: str) -> str:
    nfkd_form = unicodedata.normalize("NFKD", tag_name)
    nfkd_form.encode("ASCII", "ignore").decode("UTF-8")
    tag_name = "".join([c for c in nfkd_form if not unicodedata.combining(c)])
    tag_name = tag_name.strip().lower()
    tag_name = re.sub(r"\s+", "_", tag_name)
    tag_name = re.sub(r"[^a-zA-Z0-9_.:-]", "", tag_name)
    return tag_name


class Tag(YetiModel, database_arango.ArangoYetiConnector):
    _collection_name: ClassVar[str] = "tags"
    _root_type: Literal["tags"] = "tag"
    _type_filter: ClassVar[str | None] = None

    name: str = Field(max_length=MAX_TAG_LENGTH)
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
