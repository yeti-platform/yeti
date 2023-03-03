import datetime
from enum import Enum

from core.helpers import refang, REGEXES
from core.schemas.tag import DEFAULT_EXPIRATION_DAYS, Tag

from pydantic import BaseModel
from core import database_arango

# Data Schema
class ObservableType(str, Enum):
    ip = 'ip'
    hostname = 'hostname'
    url = 'url'
    observable = 'observable'

class ObservableTag(BaseModel):
    name: str
    fresh: bool = True
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    expiration: datetime.timedelta

class Observable(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: str = 'observables'
    _type_filter: str | None = None

    id: str | None = None
    value: str
    type: ObservableType
    created: datetime.datetime
    context: dict = {}
    tags: dict[str, ObservableTag] = {}
    last_analysis: list[dict] = []

    @classmethod
    def load(cls, object: dict) -> "Observable":
        return cls(**object)

    @classmethod
    def add_text(cls, text: str, tags: list[str] = []) -> "Observable":
        """Adds and returns an observable for a given string.

        Args:
            text: the text that will be used to add an Observable from.
            tags: a list of tags to add to the Observable.

        Returns:
            A saved Observable instance.
        """
        refanged = refang(text)
        for observable_type, regex in REGEXES:
            if not regex.match(refanged):
                continue
            observable = Observable.get_by_key_value(value=refanged)
            if observable:
                return observable.tag(tags)
            else:
                observable = Observable(
                    value=refanged,
                    type=observable_type,
                    created=datetime.datetime.now(datetime.timezone.utc)
                    ).save()
            if tags:
                observable = observable.tag(tags)
            return observable

        raise ValueError(f"Invalid observable '{text}'")

    def tag(self, tags: list[str], strict: bool = False, expiration_days: int | None = None) -> "Observable":
        """Adds tags to an observable."""
        expiration_days = expiration_days or DEFAULT_EXPIRATION_DAYS
        if strict:
            self.tags = {}
        for tag_name in tags:
            tag = Tag.get_by_key_value(name=tag_name)
            if not tag:
                tag = Tag(
                    name=tag_name,
                    created=datetime.datetime.now(datetime.timezone.utc),
                    default_expiration=datetime.timedelta(days=DEFAULT_EXPIRATION_DAYS)
                )
            tag.count += 1
            tag.save()
            observable_tag = self.tags.get(tag_name)
            if observable_tag:
                observable_tag.last_seen = datetime.datetime.now(datetime.timezone.utc)
                observable_tag.fresh = True
            else:
                self.tags[tag_name] = ObservableTag(
                    name=tag_name,
                    first_seen=datetime.datetime.now(datetime.timezone.utc),
                    last_seen=datetime.datetime.now(datetime.timezone.utc),
                    expiration=tag.default_expiration
                )
        return self.save()


# Request Schemas
class NewObservableRequest(BaseModel):
    value: str
    type: ObservableType

class ObservableUpdateRequest(BaseModel):
    context: dict | None = None
    tags: list[str] | None = None
    replace: bool

class AddTextRequest(BaseModel):
    text: str
    tags: list[str] = []

class ObservableSearchRequest(BaseModel):
    value: str | None = None
    name: str | None = None
    type: ObservableType | None = None
    tags: list[str] | None = None
    count: int = 100
    page: int = 0

class ObservableTagRequest(BaseModel):
    ids: list[str]
    tags: list[str]
    strict: bool = False
