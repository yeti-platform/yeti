import datetime
import logging
import re
from enum import Enum
from typing import ClassVar, Literal, Type

from core import database_arango
from core.helpers import now
from core.schemas.model import YetiModel
from pydantic import (BaseModel, Field, PrivateAttr, computed_field,
                      field_validator)


def future():
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        days=DEFAULT_INDICATOR_VALIDITY_DAYS
    )


DEFAULT_INDICATOR_VALIDITY_DAYS = 30


class IndicatorType(str, Enum):
    regex = "regex"
    yara = "yara"
    sigma = "sigma"
    query = "query"


class IndicatorMatch(BaseModel):
    name: str
    match: str


class DiamondModel(Enum):
    adversary = "adversary"
    capability = "capability"
    infrastructure = "infrastructure"
    victim = "victim"


class Indicator(YetiModel, database_arango.ArangoYetiConnector):
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

    pattern: str
    location: str
    diamond: DiamondModel
    kill_chain_phases: list[str] = []
    relevant_tags: list[str] = []

    @computed_field(return_type=Literal["indicator"])
    @property
    def root_type(self):
        return self._root_type

    @classmethod
    def load(cls, object: dict):
        if object["type"] in TYPE_MAPPING:
            return TYPE_MAPPING[object["type"]](**object)
        return cls(**object)

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
                        f"Indicator type {indicator.type} has not implemented match(): {error}")


class Regex(Indicator):
    _type_filter: ClassVar[str] = IndicatorType.regex
    _compiled_pattern: re.Pattern | None = PrivateAttr(None)
    type: Literal["regex"] = IndicatorType.regex

    @property
    def compiled_pattern(self):
        if not self._compiled_pattern:
            self._compiled_pattern = re.compile(self.pattern)
        return self._compiled_pattern

    @field_validator("pattern")
    @classmethod
    def validate_regex(cls, value) -> str:
        try:
            re.compile(value)
        except re.error as error:
            raise ValueError(f"Invalid regex pattern: {error}")
        return value

    def match(self, value: str) -> IndicatorMatch | None:
        result = self.compiled_pattern.search(value)
        if result:
            return IndicatorMatch(name=self.name, match=result.group())
        return None


class QueryType(str, Enum):
    opensearch = "opensearch"
    osquery = "osquery"
    sql = "sql"
    splunk = "splunk"


class Query(Indicator):
    """Represents a query that can be sent to another system."""
    _type_filter: ClassVar[str] = IndicatorType.query
    type: Literal["query"] = IndicatorType.query

    query_type: QueryType
    target_systems: list[str] = []

    def match(self, value: str) -> IndicatorMatch | None:
        return None


class Yara(Indicator):
    """Represents a Yara rule.

    Parsing and matching is yet TODO.
    """

    _type_filter: ClassVar[str] = IndicatorType.yara
    type: Literal["yara"] = IndicatorType.yara

    def match(self, value: str) -> IndicatorMatch | None:
        raise NotImplementedError


class Sigma(Indicator):
    """Represents a Sigma rule.

    Parsing and matching is yet TODO.
    """

    _type_filter: ClassVar[str] = IndicatorType.sigma
    type: Literal["sigma"] = IndicatorType.sigma

    def match(self, value: str) -> IndicatorMatch | None:
        raise NotImplementedError


TYPE_MAPPING = {
    "regex": Regex,
    "yara": Yara,
    "sigma": Sigma,
    "query": Query,
    "indicator": Indicator,
    "indicators": Indicator,
}

IndicatorTypes = Regex | Yara | Sigma | Query
IndicatorClasses = Type[Regex] | Type[Yara] | Type[Sigma] | Type[Query]
