import datetime
from enum import Enum

from core.helpers import refang, REGEXES

from pydantic import BaseModel
from core import database_arango


class Relationship(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: str = 'links'
    _type_filter: None = None

    id: str | None
    source: str
    target: str
    type: str
    description: str
    created: datetime.datetime
    modified: datetime.datetime

    @classmethod
    def load(cls, object: dict):
        return cls(**object)
