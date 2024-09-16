# TODO Observable value normalization

import datetime
import re

# from enum import Enum, EnumMeta
from typing import ClassVar, Literal

# Data Schema
# Dynamically register all observable types
import aenum
import validators
from pydantic import Field, computed_field

from core import database_arango
from core.helpers import now, refang
from core.schemas.model import YetiTagModel


class ObservableType(str, aenum.Enum):
    pass


TYPE_MAPPING = {}


class Observable(YetiTagModel, database_arango.ArangoYetiConnector):
    _collection_name: ClassVar[str] = "observables"
    _type_filter: ClassVar[str | None] = None
    _root_type: Literal["observable"] = "observable"

    value: str = Field(min_length=1)
    type: ObservableType
    created: datetime.datetime = Field(default_factory=now)
    context: list[dict] = []
    last_analysis: dict[str, datetime.datetime] = {}

    @computed_field(return_type=Literal["observable"])
    @property
    def root_type(self):
        return self._root_type

    @classmethod
    def load(cls, object: dict) -> "ObservableTypes":  # noqa: F821
        if object["type"] in TYPE_MAPPING:
            return TYPE_MAPPING[object["type"]](**object)
        raise ValueError("Attempted to instantiate an undefined observable type.")

    @classmethod
    def is_valid(cls, object: dict) -> bool:
        return validate_observable(object)

    @classmethod
    def add_text(cls, text: str, tags: list[str] = []) -> "ObservableTypes":  # noqa: F821
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
            raise ValueError(f"Invalid type for observable '{text}'")

        observable = Observable.find(value=refanged)
        if not observable:
            observable = TYPE_MAPPING[observable_type](
                value=refanged,
                created=datetime.datetime.now(datetime.timezone.utc),
            ).save()
        observable.get_tags()
        if tags:
            observable = observable.tag(tags)
        return observable

    def add_context(
        self,
        source: str,
        context: dict,
        skip_compare: set = set(),
        overwrite: bool = False,
    ) -> "ObservableTypes":  # noqa: F821
        """Adds context to an observable."""
        compare_fields = set(context.keys()) - skip_compare - {"source"}

        found_idx = -1
        temp_context = {key: context.get(key) for key in compare_fields}

        for idx, db_context in enumerate(list(self.context)):
            if db_context["source"] != source:
                continue
            if overwrite:
                found_idx = idx
                break
            temp_db = {key: db_context.get(key) for key in compare_fields}

            if temp_db == temp_context:
                found_idx = idx
                break

        context["source"] = source
        if found_idx != -1:
            self.context[found_idx] = context
        else:
            self.context.append(context)

        return self.save()

    def delete_context(
        self, source: str, context: dict, skip_compare: set = set()
    ) -> "ObservableTypes":  # noqa: F821
        """Deletes context from an observable."""
        compare_fields = set(context.keys()) - skip_compare - {"source"}
        for idx, db_context in enumerate(list(self.context)):
            if db_context["source"] != source:
                continue
            for field in compare_fields:
                if db_context.get(field) != context.get(field):
                    break
            else:
                del self.context[idx]
                break
        return self.save()


TYPE_MAPPING.update({"observable": Observable, "observables": Observable})


TYPE_VALIDATOR_MAP = {}


TYPE_VALIDATOR_MAP = {
    ObservableType.ipv4: validators.ipv4,
    ObservableType.ipv6: validators.ipv6,
    ObservableType.sha256: validators.sha256,
    ObservableType.sha1: validators.sha1,
    ObservableType.md5: validators.md5,
    ObservableType.hostname: validators.domain,
    ObservableType.url: validators.url,
    ObservableType.email: validators.email,
    ObservableType.iban: validators.iban,
}

REGEXES_OBSERVABLES = {
    # Unix
    ObservableType.path: [
        re.compile(r"^(\/[^\/\0]+)+$"),
        re.compile(r"^(?:[a-zA-Z]\:|\\\\[\w\.]+\\[\w.$]+)\\(?:[\w]+\\)*\w([\w.])+"),
    ],
    ObservableType.bic: [re.compile("^[A-Z]{6}[A-Z0-9]{2}[A-Z0-9]{3}?")],
}


def validate_observable(obs: Observable) -> bool:
    if obs.type in TYPE_VALIDATOR_MAP:
        return TYPE_VALIDATOR_MAP[obs.type](obs.value) is True
    elif obs.type in dict(REGEXES_OBSERVABLES):
        for regex in REGEXES_OBSERVABLES[obs.type]:
            if regex.match(obs.value):
                return True
        return False
    else:
        return False


def find_type(value: str) -> ObservableType | None:
    for obs_type, validator in TYPE_VALIDATOR_MAP.items():
        if validator(value):
            return obs_type
    for obs_type, regexes in REGEXES_OBSERVABLES.items():
        for regex in regexes:
            if regex.match(value):
                return obs_type
    return None


TYPE_MAPPING = {"observable": Observable, "observables": Observable}