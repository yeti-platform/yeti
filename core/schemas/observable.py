#TODO Observable value normalization

import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field

from core import database_arango
from core.helpers import REGEXES, refang
from core.schemas.entity import Entity
from core.schemas.tag import DEFAULT_EXPIRATION_DAYS, Tag


def now():
    return datetime.datetime.now(datetime.timezone.utc)

# Data Schema
class ObservableType(str, Enum):
    ip = 'ip'
    hostname = 'hostname'
    url = 'url'
    observable = 'observable'
    guess = 'guess'

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
    created: datetime.datetime = Field(default_factory=now)
    context: list[dict] = []
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
            observable = Observable.find(value=refanged)
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
        #TODO: Tag replacement / propagation
        expiration_days = expiration_days or DEFAULT_EXPIRATION_DAYS
        if strict:
            self.tags = {}
        for tag_name in tags:
            tag = Tag.find(name=tag_name)
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
            relevant_entities = Entity.filter(args={'relevant_tags': [tag_name]})
            for entity in relevant_entities:
                self.link_to(entity, 'tags', 'Tagged')
        return self.save()

    def add_context(self, source: str, context: dict, skip_compare: set = set()) -> "Observable":
        """Adds context to an observable."""
        compare_fields = set(context.keys()) - skip_compare - {'source'}
        for idx, db_context in enumerate(list(self.context)):
            if db_context['source'] != source:
                continue
            for field in compare_fields:
                if db_context.get(field) != context.get(field):
                    context['source'] = source
                    self.context[idx] = context
                    break
            else:
                db_context.update(context)
                break
        else:
            context['source'] = source
            self.context.append(context)
        return self.save()

    def delete_context(self, source: str, context: dict, skip_compare: set = set()) -> "Observable":
        """Deletes context from an observable."""
        compare_fields = set(context.keys()) - skip_compare - {'source'}
        for idx, db_context in enumerate(list(self.context)):
            if db_context['source'] != source:
                continue
            for field in compare_fields:
                if db_context.get(field) != context.get(field):
                    break
            else:
                del self.context[idx]
                break
        return self.save()

TYPE_MAPPING = {
    'ip': Observable,
    'hostname': Observable,
    'url': Observable,
    'observable': Observable,
}

# Request Schemas
#TODO: Move these to the API modules.
class NewObservableRequest(BaseModel):
    value: str
    tags: list[str] = []
    type: ObservableType

class NewBulkObservableAddRequest(BaseModel):
    observables: list[NewObservableRequest]

class AddTextRequest(BaseModel):
    text: str
    tags: list[str] = []

class AddContextRequest(BaseModel):
    source: str
    context: dict
    skip_compare: set = set()

class DeleteContextRequest(AddContextRequest):
    pass

class ObservableSearchRequest(BaseModel):
    value: str | None = None
    name: str | None = None
    type: ObservableType | None = None
    tags: list[str] | None = None
    count: int
    page: int

class ObservableTagRequest(BaseModel):
    ids: list[str]
    tags: list[str]
    strict: bool = False
