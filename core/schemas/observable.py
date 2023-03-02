import datetime
from enum import Enum

from core.helpers import refang, REGEXES

from pydantic import BaseModel
from core import database_arango

# Data Schema
class ObservableType(str, Enum):
    ip = 'ip'
    hostname = 'hostname'
    url = 'url'
    observable = 'observable'

class Observable(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: str = 'observables'
    _type_filter: str | None = None

    id: str | None = None
    value: str
    type: ObservableType
    created: datetime.datetime
    context: dict = {}
    tags: list[str] = []
    last_analysis: list[dict] = []

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
            results: list[Observable] = Observable.filter({"value": refanged}, offset=0, count=1)
            if results:
                return results[0]

            observable = Observable(
                value=refanged,
                type=observable_type,
                created=datetime.datetime.now(datetime.timezone.utc)
                ).save()
            return observable

        raise ValueError(f"Invalid observable '{text}'")

        # o = observable_type.get_or_create(value=text)
        # if tags:
        #     o.tag(tags)
        # return o


# Request Schemas
class NewObservableRequest(BaseModel):
    value: str
    type: ObservableType

class ObservableUpdateRequest(BaseModel):
    context: dict | None = None
    tags: list[str] | None = None
    replace: bool

class AddTextRequest(BaseModel):
    text: str
    tags: list[str] = []

class ObservableSearchRequest(BaseModel):
    value: str | None = None
    name: str | None = None
    type: ObservableType | None = None
    tags: list[str] | None = None
    count: int = 100
    page: int = 0
