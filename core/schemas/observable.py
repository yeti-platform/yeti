# TODO Observable value normalization

import datetime
import re
from enum import Enum
from typing import ClassVar, Literal

import validators
from pydantic import Field, computed_field

from core import database_arango
from core.helpers import now, refang
from core.schemas.model import YetiTagModel


# Data Schema
class ObservableType(str, Enum):
    asn = "asn"
    bic = "bic"
    certificate = "certificate"
    cidr = "cidr"
    command_line = "command_line"
    docker_image = "docker_image"
    email = "email"
    file = "file"
    guess = "guess"
    hostname = "hostname"
    iban = "iban"
    imphash = "imphash"
    ipv4 = "ipv4"
    ipv6 = "ipv6"
    mac_address = "mac_address"
    md5 = "md5"
    generic = "generic"
    path = "path"
    registry_key = "registry_key"
    sha1 = "sha1"
    sha256 = "sha256"
    ssdeep = "ssdeep"
    tlsh = "tlsh"
    url = "url"
    user_agent = "user_agent"
    user_account = "user_account"
    wallet = "wallet"


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
        if tags:
            observable = observable.tag(tags)
        return observable

    def add_context(
        self, source: str, context: dict, skip_compare: set = set()
    ) -> "ObservableTypes":  # noqa: F821
        """Adds context to an observable."""
        compare_fields = set(context.keys()) - skip_compare - {"source"}
        for idx, db_context in enumerate(list(self.context)):
            if db_context["source"] != source:
                continue
            for field in compare_fields:
                if db_context.get(field) != context.get(field):
                    context["source"] = source
                    self.context[idx] = context
                    break
            else:
                db_context.update(context)
                break
        else:
            context["source"] = source
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


# Import all observable types, as these register themselves in the TYPE_MAPPING
# disable: pylint=wrong-import-position
from core.schemas.observables import (  # noqa: E402
    asn,  # noqa: F401
    bic,  # noqa: F401
    certificate,  # noqa: F401
    cidr,  # noqa: F401
    command_line,  # noqa: E402, F401
    docker_image,  # noqa: F401
    email,  # noqa: F401
    file,  # noqa: F401
    generic_observable,  # noqa: F401
    hostname,  # noqa: F401
    iban,  # noqa: F401
    imphash,  # noqa: F401
    ipv4,  # noqa: F401
    ipv6,  # noqa: F401
    mac_address,  # noqa: F401
    md5,  # noqa: F401
    path,  # noqa: F401
    registry_key,  # noqa: F401
    sha1,  # noqa: F401
    sha256,  # noqa: F401
    ssdeep,  # noqa: F401
    tlsh,  # noqa: F401
    url,  # noqa: F401
    user_account,  # noqa: F401
    user_agent,  # noqa: F401
    wallet,  # noqa: F401
)
