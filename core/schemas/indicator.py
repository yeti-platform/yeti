import datetime
import logging
from enum import Enum
from typing import ClassVar, Literal

from pydantic import BaseModel, Field, computed_field

from core import database_arango
from core.helpers import now
from core.schemas.model import YetiTagModel


def future():
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        days=DEFAULT_INDICATOR_VALIDITY_DAYS
    )


DEFAULT_INDICATOR_VALIDITY_DAYS = 30


# forward declarations
class IndicatorType(str, Enum):
    ...


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
    type: str
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
