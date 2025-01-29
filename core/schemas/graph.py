import datetime
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, computed_field

from core import database_arango
from core.schemas import roles

# Database model


class GraphFilter(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    key: str
    value: str
    operator: str


# Relationship and TagRelationship do not inherit from YetiModel
# because they represent and id in the form of collection_name/id
class Relationship(BaseModel, database_arango.ArangoYetiConnector):
    model_config = ConfigDict(str_strip_whitespace=True)
    _exclude_overwrite: list[str] = list()
    _collection_name: ClassVar[str] = "links"
    _type_filter: ClassVar[str | None] = None
    _root_type: Literal["relationship"] = "relationship"
    __id: str | None = None

    source: str
    target: str
    type: str
    count: int = 1
    description: str
    created: datetime.datetime
    modified: datetime.datetime

    def __init__(self, **data):
        super().__init__(**data)
        self.__id = data.get("__id", None)

    @computed_field(return_type=Literal["relationship"])
    @property
    def root_type(self):
        return self._root_type

    @computed_field(return_type=str)
    @property
    def id(self):
        return self.__id

    @classmethod
    def load(cls, object: dict):
        return cls(**object)


class TagRelationship(BaseModel, database_arango.ArangoYetiConnector):
    model_config = ConfigDict(str_strip_whitespace=True)
    _exclude_overwrite: list[str] = list()
    _collection_name: ClassVar[str] = "tagged"
    _root_type: Literal["tag_relationship"] = "tag_relationship"
    _type_filter: None = None
    __id: str | None = None

    source: str
    target: str
    last_seen: datetime.datetime
    expires: datetime.datetime | None = None
    fresh: bool

    def __init__(self, **data):
        super().__init__(**data)
        self.__id = data.get("__id", None)

    @computed_field(return_type=Literal["tag_relationship"])
    @property
    def root_type(self):
        return self._root_type

    @computed_field(return_type=str)
    @property
    def id(self):
        return self.__id

    @classmethod
    def load(cls, object: dict):
        return cls(**object)


class RoleRelationship(BaseModel, database_arango.ArangoYetiConnector):
    model_config = ConfigDict(str_strip_whitespace=True)
    _exclude_overwrite: list[str] = list()
    _collection_name: ClassVar[str] = "acls"
    _type_filter: ClassVar[str | None] = None
    _root_type: Literal["acl"] = "acl"
    __id: str | None = None

    source: str
    target: str
    role: roles.Permission
    created: datetime.datetime
    modified: datetime.datetime

    def __init__(self, **data):
        super().__init__(**data)
        self.__id = data.get("__id", data.get("_key", None))

    @computed_field(return_type=Literal["acl"])
    @property
    def root_type(self):
        return self._root_type

    @computed_field(return_type=str)
    @property
    def id(self):
        return self.__id

    @classmethod
    def load(cls, object: dict):
        return cls(**object)

    @classmethod
    def has_permissions(cls, src, target_id: str, permission: roles.Permission) -> bool:
        vertices, paths, total = src.neighbors(
            graph="acls", direction="outbound", max_hops=2
        )
        for path in paths:
            for edge in path:
                if edge.role & permission == permission and edge.target == target_id:
                    return True
        return False


RelationshipTypes = Relationship | TagRelationship | RoleRelationship
