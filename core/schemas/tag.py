import datetime
from enum import Enum

from core.helpers import refang, REGEXES

from pydantic import BaseModel
from core import database_arango

DEFAULT_EXPIRATION_DAYS = 30  # Completely arbitrary


class Tag(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: str = 'tags'
    _type_filter: str | None = None

    id: str | None = None
    name: str
    count: int = 0
    created: datetime.datetime
    default_expiration: datetime.timedelta
    produces: list[str] = []
    replaces: list[str] = []

    @classmethod
    def load(cls, object: dict) -> "Tag":
        return cls(**object)

class NewRequest(BaseModel):
    name: str
    default_expiration_days: int = DEFAULT_EXPIRATION_DAYS
    produces: list[str] = []
    replaces: list[str] = []

class UpdateRequest(NewRequest):
    pass

class TagSearchRequest(BaseModel):
    name: str | None = None
    produces: list[str] = []
    replaces: list[str] = []
    count: int
    page: int
