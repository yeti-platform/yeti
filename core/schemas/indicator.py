import datetime
import logging
from enum import Enum
from typing import Any, ClassVar, List, Literal

from pydantic import ConfigDict, Field, computed_field

from core import database_arango
from core.helpers import now
from core.schemas.model import YetiAclModel, YetiContextModel, YetiTagModel


def future():
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        days=DEFAULT_INDICATOR_VALIDITY_DAYS
    )


DEFAULT_INDICATOR_VALIDITY_DAYS = 30


# Forward declarations
# They are then populated by the load_indicators function in __init__.py
class IndicatorType(str, Enum): ...


IndicatorTypes = ()
TYPE_MAPPING = {}


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

    def save(self, *args, **kwargs) -> "Indicator":
        self.modified = now()
        return super().save(*args, **kwargs)

    def match(self, value: str) -> Any | None:
        raise NotImplementedError

    @classmethod
    def search(cls, observables: list[str]) -> list[tuple[str, "Indicator"]]:
        indicators = list(Indicator.list())
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
    tags: List[str] = None,
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
