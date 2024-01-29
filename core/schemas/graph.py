import datetime
from typing import ClassVar

from core import database_arango
from pydantic import BaseModel, computed_field


# Database model
# Relationship and TagRelationship do not inherit from YetiModel
# because they represent and id in the form of collection_name/id
class Relationship(BaseModel, database_arango.ArangoYetiConnector):
    _collection_name: ClassVar[str] = "links"
    _type_filter: ClassVar[str | None] = None
    __id: str | None = None

    source: str
    target: str
    type: str
    description: str
    created: datetime.datetime
    modified: datetime.datetime

    def __init__(self, **data):
        super().__init__(**data)
        self.__id = data.get("__id", None)

    @computed_field(return_type=str)
    @property
    def id(self):
        return self.__id

    @classmethod
    def load(cls, object: dict):
        return cls(**object)


class TagRelationship(BaseModel, database_arango.ArangoYetiConnector):
    _type_filter: None = None
    __id: str | None = None

    source: str
    target: str
    last_seen: datetime.datetime
    fresh: bool

    def __init__(self, **data):
        super().__init__(**data)
        self.__id = data.get("__id", None)

    @computed_field(return_type=str)
    @property
    def id(self):
        return self.__id

    @classmethod
    def load(cls, object: dict):
        return cls(**object)


RelationshipTypes = Relationship | TagRelationship
