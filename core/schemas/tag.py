import datetime

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
