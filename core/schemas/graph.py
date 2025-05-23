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
    pathcompare: str = "ANY"


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
    def has_permissions(
        cls, user, target_id: str, permission: roles.Permission
    ) -> bool:
        acl_acl = """
         WITH observables, entities, dfiq, indicators
        FOR v, e IN 1..2 outbound @user_extended_id acls
          OPTIONS { uniqueVertices: "path" }
        FILTER e.target == @target_id
        RETURN e
        """

        results = cls._db.aql.execute(
            acl_acl,
            bind_vars={"target_id": target_id, "user_extended_id": user.extended_id},
        )
        for edge in results:
            if edge["role"] & permission == permission and edge["target"] == target_id:
                return True
        return False


RelationshipTypes = Relationship | RoleRelationship
