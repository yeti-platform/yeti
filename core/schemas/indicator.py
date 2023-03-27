import re
import datetime

from pydantic import BaseModel, Field, validator, PrivateAttr
from core import database_arango

def now():
    return datetime.datetime.now(datetime.timezone.utc)

def future():
    return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=DEFAULT_INDICATOR_VALIDITY_DAYS)

DEFAULT_INDICATOR_VALIDITY_DAYS = 30

class IndicatorMatch(BaseModel):
    name: str
    match: str

class Indicator(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: str = 'indicators'
    _type_filter: str = ''

    id: str | None = None
    name: str
    description: str = ''
    created: datetime.datetime = Field(default_factory=now)
    modified: datetime.datetime = Field(default_factory=now)
    valid_from: datetime.datetime = Field(default_factory=now)
    valid_until: datetime.datetime = Field(default_factory=future)

    pattern: str
    location: str
    kill_chain_phases: list[str] = []

    @classmethod
    def load(cls, object: dict):
        if object['type'] in TYPE_MAPPING:
            return TYPE_MAPPING[object['type']](**object)
        return cls(**object)

    def match(self, value: str) -> IndicatorMatch | None:
        raise NotImplementedError

    @classmethod
    def search(cls, observables: list[str]) -> list[tuple[str, "Indicator"]]:
        indicators = list(Indicator.list())
        for observable in observables:
            for indicator in indicators:
                if indicator.match(observable):
                    yield observable, indicator

class Regex(Indicator):
    _type_filter: str = 'regex'
    _compiled_pattern: re.Pattern | None = PrivateAttr(None)
    type: str = Field('regex', const=True)

    @property
    def compiled_pattern(self):
        if not self._compiled_pattern:
            self._compiled_pattern = re.compile(self.pattern)
        return self._compiled_pattern

    @validator('pattern')
    def validate_regex(cls, value) -> str:
        try:
            re.compile(value)
        except re.error as error:
            raise ValueError(f'Invalid regex pattern: {error}')
        return value

    def match(self, value: str) -> IndicatorMatch | None:
        result = self.compiled_pattern.search(value)
        if result:
            return IndicatorMatch(name=self.name, match=result.group())
        return None


TYPE_MAPPING = {
    'regex': Regex,
}

#TODO: Indicator tyeps: yara, sigma
