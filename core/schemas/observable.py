#TODO Observable value normalization

import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field
import validators
from core import database_arango
from core.helpers import refang
from core.schemas.entity import Entity
from core.schemas.tag import DEFAULT_EXPIRATION_DAYS, Tag
from core.schemas.graph import TagRelationship
from core.helpers import now


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
    path = 'path'
    mac_address = 'mac_address'
    command_line = 'command_line'
    registry_key = 'registry_key'


class Observable(BaseModel, database_arango.ObservableYetiConnector):
    _collection_name: str = 'observables'
    _type_filter: str | None = None

    root_type: str = Field('observable', const=True)
    id: str | None = None
    value: str
    tags: dict[str, TagRelationship] = {}
    type: ObservableType
    created: datetime.datetime = Field(default_factory=now)
    context: list[dict] = []
    last_analysis: dict[str, datetime.datetime] = {}

    @classmethod
    def load(cls, object: dict) -> "Observable":
        return cls(**object)
    @classmethod
    def is_valid(cls, object: dict) -> bool:
        return validate_observable(object)
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
        observable_type = find_type(refanged)
        if not observable_type:
            raise ValueError(f"Invalid observable '{text}'")

        observable = Observable.find(value=refanged)
        if not observable:
            observable = Observable(
                value=refanged,
                type=observable_type,
                created=datetime.datetime.now(datetime.timezone.utc)
                ).save()
        if tags:
            observable = observable.tag(tags)
        return observable

    def tag(self,
            tags: list[str],
            strict: bool = False,
            expiration_days: int | None = None) -> "Observable":
        """Connects observable to tag graph."""
        expiration_days = expiration_days or DEFAULT_EXPIRATION_DAYS

        if strict:
            self.observable_clear_tags()

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

            tag_link = self.observable_tag(tag.name)
            self.tags[tag.name] = tag_link

            extra_tags |= set(tag.produces)

            relevant_entities, _ = Entity.filter(args={'relevant_tags': [tag.name]})
            for entity in relevant_entities:
                self.link_to(entity, 'tags', 'Tagged')

        extra_tags -= set(tags)
        if extra_tags:
            self.tag(list(extra_tags))

        return self

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


TYPE_VALIDATOR_MAP = {
    ObservableType.ip: validators.ipv4,
    ObservableType.bitcoin_wallet: validators.btc_address,
    ObservableType.sha256: validators.sha256,
    ObservableType.sha1: validators.sha1,
    ObservableType.md5: validators.md5,
    ObservableType.hostname: validators.domain,
    ObservableType.url: validators.url,
    ObservableType.email: validators.email,
}

REGEXES_OBSERVABLES = {}

def validate_observable(obs: Observable) -> bool:
    if obs.type in TYPE_VALIDATOR_MAP:
        return TYPE_VALIDATOR_MAP[obs.type](obs.value)
    elif obs.type in dict(REGEXES_OBSERVABLES):
        return dict(REGEXES_OBSERVABLES)[obs.type].match(obs.value)
    else:
        return False


def find_type(value: str) -> ObservableType | None:
    for obs_type in TYPE_VALIDATOR_MAP:
        if TYPE_VALIDATOR_MAP[obs_type](value):
            return obs_type
    for type_obs, regex in REGEXES_OBSERVABLES.items():
        if regex.match(value):
            return type_obs
        else:
            None
    return None

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
