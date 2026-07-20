from __future__ import annotations

import datetime
import logging
from enum import Enum
from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    Generator,
    List,
    Literal,
    Self,
    Union,
)

from pydantic import ConfigDict, Field, computed_field

from core import database_arango
from core.helpers import now
from core.schemas.model import YetiAclModel, YetiContextModel, YetiTagModel


def future():
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        days=DEFAULT_INDICATOR_VALIDITY_DAYS
    )


DEFAULT_INDICATOR_VALIDITY_DAYS = 30

# IndicatorType, IndicatorTypes and TYPE_MAPPING are defined statically at the
# bottom of this module (see "Static type registry"). TYPE_MAPPING must exist
# before the functions below are *called*, which is always the case at runtime.
TYPE_MAPPING: dict[str, type["Indicator"]] = {}


class DiamondModel(Enum):
    adversary = "adversary"
    capability = "capability"
    infrastructure = "infrastructure"
    victim = "victim"


class Indicator(
    YetiTagModel, YetiAclModel, YetiContextModel, database_arango.ArangoYetiConnector
):
    model_config = ConfigDict(str_strip_whitespace=True)
    _collection_name: ClassVar[str] = "indicators"
    _type_filter: ClassVar[str] = ""
    _root_type: Literal["indicator"] = "indicator"

    if TYPE_CHECKING:
        # Each concrete indicator subclass declares `type` as its own
        # Literal[IndicatorType.*] field. Declared here as a property
        # (type-check time only, so not a required field) so code holding a base
        # Indicator can resolve `.type`.
        @property
        def type(self) -> "IndicatorType": ...

    name: str
    description: str = ""
    created: datetime.datetime = Field(default_factory=now)
    modified: datetime.datetime = Field(default_factory=now)
    valid_from: datetime.datetime = Field(default_factory=now)
    valid_until: datetime.datetime = Field(default_factory=future)

    pattern: str = Field(min_length=1)
    location: str = ""
    diamond: DiamondModel
    kill_chain_phases: list[str] = []
    relevant_tags: list[str] = []

    @computed_field(return_type=Literal["indicator"])
    @property
    def root_type(self):
        return self._root_type

    @classmethod
    def load(cls, object: dict) -> "IndicatorTypes":
        if cls._type_filter:
            loader = TYPE_MAPPING[cls._type_filter]
        elif object["type"] in TYPE_MAPPING:
            loader = TYPE_MAPPING[object["type"]]
        else:
            raise ValueError("Attempted to instantiate an undefined indicator type.")
        return loader(**object)

    def save(self, *args, **kwargs) -> "Self":
        self.modified = now()
        return super().save(*args, **kwargs)

    def match(self, value: str) -> Any | None:
        raise NotImplementedError

    @classmethod
    def search(
        cls, observables: list[str]
    ) -> Generator[tuple[str, "Indicator"], None, None]:
        indicators = list(cls.list())
        for observable in observables:
            for indicator in indicators:
                try:
                    if indicator.match(observable):
                        yield observable, indicator
                except NotImplementedError as error:
                    logging.error(
                        f"Indicator type {indicator.type} has not implemented match(): {error}"
                    )


def create(
    *, name: str, type: str, pattern: str, diamond: DiamondModel, **kwargs
) -> "IndicatorTypes":
    """
    Create an indicator of the given type without saving it to the database.

    type is a string representing the type of indicator to create.
    If the type is not valid, a ValueError is raised.

    kwargs must contain "name" and "diamond" fields and will be handled by
    pydantic.
    """
    if type not in TYPE_MAPPING:
        raise ValueError(f"{type} is not a valid indicator type")
    return TYPE_MAPPING[type](name=name, pattern=pattern, diamond=diamond, **kwargs)


def save(
    *,
    name: str,
    type: str,
    pattern: str,
    diamond: DiamondModel,
    tags: List[str] | None = None,
    **kwargs,
):
    indicator_obj = create(
        name=name, type=type, pattern=pattern, diamond=diamond, **kwargs
    ).save()
    if tags:
        indicator_obj.tag(tags)
    return indicator_obj


def find(*, name: str, **kwargs) -> "IndicatorTypes":
    return Indicator.find(name=name, **kwargs)


# ---------------------------------------------------------------------------
# Static type registry (see observable.py for the rationale).
# ---------------------------------------------------------------------------
from core.schemas.indicators.forensicartifact import ForensicArtifact  # noqa: E402
from core.schemas.indicators.query import Query  # noqa: E402
from core.schemas.indicators.regex import Regex  # noqa: E402
from core.schemas.indicators.sigma import Sigma  # noqa: E402
from core.schemas.indicators.suricata import Suricata  # noqa: E402
from core.schemas.indicators.yara import Yara  # noqa: E402
from core.schemas.loader import load_private_types  # noqa: E402


class IndicatorType(str, Enum):
    forensicartifact = "forensicartifact"
    query = "query"
    regex = "regex"
    sigma = "sigma"
    suricata = "suricata"
    yara = "yara"


_INDICATOR_CLASSES: list[type[Indicator]] = [
    ForensicArtifact,
    Query,
    Regex,
    Sigma,
    Suricata,
    Yara,
]

_private_indicator_classes = load_private_types("core.schemas.indicators", Indicator)

TYPE_MAPPING = {"indicator": Indicator, "indicators": Indicator}
for _cls in (*_INDICATOR_CLASSES, *_private_indicator_classes):
    TYPE_MAPPING[str(_cls.model_fields["type"].default)] = _cls

IndicatorTypes = Union[
    ForensicArtifact,
    Query,
    Regex,
    Sigma,
    Suricata,
    Yara,
]
if _private_indicator_classes:
    IndicatorTypes = Union[(IndicatorTypes, *_private_indicator_classes)]
