import datetime

from pydantic import BaseModel, Field

from core import database_arango

DEFAULT_EXPIRATION_DAYS = 30  # Completely arbitrary

def now():
    return datetime.datetime.now(datetime.timezone.utc)

def future():
    return datetime.timedelta(days=DEFAULT_EXPIRATION_DAYS)


class Tag(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: str = 'tags'
    _type_filter: str | None = None

    id: str | None = None
    name: str
    count: int = 0
    created: datetime.datetime = Field(default_factory=now)
    default_expiration: datetime.timedelta = Field(default_factory=future)
    produces: list[str] = []
    replaces: list[str] = []

    @classmethod
    def load(cls, object: dict) -> "Tag":
        return cls(**object)
