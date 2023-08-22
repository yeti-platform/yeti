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
    email = 'email'
    file = 'file'
    sha256 = 'sha256'
    sha1 = 'sha1'
    md5 = 'md5'
    asn = 'asn'
    cidr = 'cidr'
    certificate = 'certificate'
    bitcoin_wallet = 'bitcoin_wallet'


class ObservableTag(BaseModel):
    name: str
    fresh: bool = True
    first_seen: datetime.datetime = Field(default_factory=now)
    last_seen: datetime.datetime = Field(default_factory=now)
    expiration: datetime.timedelta

class Observable(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: str = 'observables'
    _type_filter: str | None = None

    root_type: str = Field('observable', const=True)
    id: str | None = None
    value: str
    type: ObservableType
    created: datetime.datetime = Field(default_factory=now)
    context: list[dict] = []
    tags: dict[str, ObservableTag] = {}
    last_analysis: dict[str, datetime.datetime] = {}

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
        expiration_days = expiration_days or DEFAULT_EXPIRATION_DAYS
        if strict:
            self.tags = {}

        extra_tags = set()
        for tag_name in tags:
            # Attempt to find replacement tag
            replacements, _ = Tag.filter({"in__replaces": [tag_name]}, count=1)
            tag: Optional[Tag]

            if replacements:
                tag = replacements[0]
            # Attempt to find actual tag
            else:
                tag = Tag.find(name=tag_name)
            # Create tag
            if not tag:
                tag = Tag(name=tag_name).save()

            observable_tag = self.tags.get(tag.name)
            if observable_tag:
                observable_tag.last_seen = datetime.datetime.now(datetime.timezone.utc)
                observable_tag.fresh = True
            else:
                self.tags[tag.name] = ObservableTag(
                    name=tag.name,expiration=tag.default_expiration)
                tag.count += 1
                tag = tag.save()

            extra_tags |= set(tag.produces)

            relevant_entities, _ = Entity.filter(args={'relevant_tags': [tag.name]})
            for entity in relevant_entities:
                self.link_to(entity, 'tags', 'Tagged')

        extra_tags -= set(tags)
        if extra_tags:
            self.tag(list(extra_tags))

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
    'observables': Observable,
    'observable': Observable,
    'file': Observable,
    'sha256': Observable,
    'sha1': Observable,
    'md5': Observable,
    'asn': Observable,
    'cidr': Observable,
    'email': Observable,
    'asn': Observable,
}
