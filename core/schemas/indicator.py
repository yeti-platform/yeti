import datetime
import logging
from enum import Enum
from typing import ClassVar, List, Literal

from core import database_arango
from core.helpers import now
from core.schemas.model import YetiTagModel
from pydantic import BaseModel, Field, computed_field


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


class IndicatorMatch(BaseModel):
    name: str
    match: str


class DiamondModel(Enum):
    adversary = "adversary"
    capability = "capability"
    infrastructure = "infrastructure"
    victim = "victim"


class Indicator(YetiTagModel, database_arango.ArangoYetiConnector):
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

    def match(self, value: str) -> IndicatorMatch | None:
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


def create(type: str, **kwargs) -> "IndicatorTypes":
    """
    Create an indicator of the given type without saving it to the database.

    type is a string representing the type of indicator to create.
    If the type is not valid, a ValueError is raised.

    kwargs must contain "name" and "diamond" fields and will be handled by
    pydantic.
    """
    if type not in TYPE_MAPPING:
        raise ValueError(f"{type} is not a valid indicator type")
    return TYPE_MAPPING[type](**kwargs)


def save(type: str, tags: List[str] = None, **kwargs):
    indicator_obj = create(type, **kwargs).save()
    if tags:
        indicator_obj.tag(tags)
    return indicator_obj


def get(**kwargs) -> "IndicatorTypes":
    if "name" not in kwargs:
        raise ValueError("value is a required field for an indicator")
    return Indicator.find(**kwargs)
