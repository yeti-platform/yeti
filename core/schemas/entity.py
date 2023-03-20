import datetime
from enum import Enum

from core.helpers import refang, REGEXES

from pydantic import BaseModel, Field
from core import database_arango

def now():
    return datetime.datetime.now(datetime.timezone.utc)


class Entity(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: str = 'entities'

    id: str | None = None
    name: str
    description: str = ''
    # created: datetime.datetime
    created: datetime.datetime = Field(default_factory=now)
    modified: datetime.datetime = Field(default_factory=now)
    relevant_tags: list[str] = []

    @classmethod
    def load(cls, object: dict):
        if object['type'] in TYPE_MAPPING:
            return TYPE_MAPPING[object['type']](**object)
        return cls(**object)


class Actor(Entity):
    _type_filter: str = 'actor'
    type: str = Field('actor', const=True)
    aliases: list[str] = []

TYPE_MAPPING = {
    'actor': Actor,
}
