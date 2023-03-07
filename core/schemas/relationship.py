import datetime
from enum import Enum

from core.helpers import refang, REGEXES

from pydantic import BaseModel
from core import database_arango


class Relationship(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: str = 'relationships'
    _type_filter: None

    type: str
    description: str
    created: datetime.datetime
    modified: datetime.datetime

    @classmethod
    def load(cls, **kwargs):
        return cls(**kwargs)
