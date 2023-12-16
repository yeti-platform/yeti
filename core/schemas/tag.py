import datetime
import re
import unicodedata
from typing import ClassVar

from core import database_arango
from core.helpers import now
from core.schemas.model import YetiModel
from pydantic import BaseModel, Field

DEFAULT_EXPIRATION = datetime.timedelta(days=30)  # Completely arbitrary

def future():
    return DEFAULT_EXPIRATION

def normalize_name(tag_name: str) -> str:
    nfkd_form = unicodedata.normalize("NFKD", tag_name)
    nfkd_form.encode("ASCII", "ignore").decode("UTF-8")
    tag_name = "".join(
        [c for c in nfkd_form if not unicodedata.combining(c)]
    )
    tag_name = tag_name.strip().lower()
    tag_name = re.sub(r"\s+", "_", tag_name)
    tag_name = re.sub(r"[^a-zA-Z0-9_:-]", "", tag_name)
    return tag_name

class Tag(YetiModel, database_arango.ArangoYetiConnector):
    _collection_name: ClassVar[str] = "tags"
    _type_filter: ClassVar[str | None] = None

    #id: str | None = None
    name: str
    count: int = 0
    created: datetime.datetime = Field(default_factory=now)
    default_expiration: datetime.timedelta = DEFAULT_EXPIRATION
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
