import datetime
from enum import Enum

from pydantic import BaseModel

from core import database_arango

# Database model
class Relationship(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: str = 'links'
    _type_filter: None = None

    id: str | None = None
    source: str
    target: str
    type: str
    description: str
    created: datetime.datetime
    modified: datetime.datetime

    @classmethod
    def load(cls, object: dict):
        return cls(**object)


class TagRelationship(BaseModel, database_arango.ArangoYetiConnector):
    _type_filter: None = None

    id: str | None = None
    source: str
    target: str
    last_seen: datetime.datetime
    fresh: bool

    @classmethod
    def load(cls, object: dict):
        return cls(**object)
