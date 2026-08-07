import datetime
import re
from typing import Annotated, ClassVar, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

from core import database_arango
from core.schemas import roles

# Database model


class GraphFilter(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    key: str
    value: str
    operator: str
    pathcompare: str = "ANY"


class GraphExploreFilter(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    key: str
    value: str
    operator: Literal["=~", "==", "in"] = "=="
    pathcompare: Literal["ANY", "ALL", "NONE"] = "ANY"

    @field_validator("key")
    @classmethod
    def validate_key(cls, value: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9_.]+", value):
            raise ValueError("filter key contains unsupported characters")
        return value


class GraphExploreItemScope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["items"] = "items"
    items: Annotated[list[str], Field(min_length=1, max_length=100)]

    @field_validator("items")
    @classmethod
    def validate_items(cls, values: list[str]) -> list[str]:
        deduplicated = list(dict.fromkeys(values))
        for value in deduplicated:
            if not re.fullmatch(
                r"(?:observables|entities|indicators|dfiq)/[a-zA-Z0-9_:-]+", value
            ):
                raise ValueError("items must contain valid Yeti extended IDs")
        return deduplicated


GraphQueryValue = str | int | list[str | int]


class GraphExploreQueryScope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["query"] = "query"
    query: dict[str, GraphQueryValue] = Field(default_factory=dict)
    sorting: list[tuple[str, bool]] = Field(default_factory=list, max_length=10)
    filter_aliases: list[tuple[str, Literal["text", "option", "list"]]] = Field(
        default_factory=list, max_length=20
    )

    @model_validator(mode="after")
    def validate_fields(self):
        safe_field = re.compile(r"[a-zA-Z0-9_.~]+")
        for field in self.query:
            if not safe_field.fullmatch(field):
                raise ValueError("query field contains unsupported characters")
        for field, _ in self.sorting:
            if not safe_field.fullmatch(field):
                raise ValueError("sort field contains unsupported characters")
        for field, _ in self.filter_aliases:
            if not safe_field.fullmatch(field):
                raise ValueError("filter alias contains unsupported characters")
        return self


GraphExploreScope = Annotated[
    GraphExploreItemScope | GraphExploreQueryScope, Field(discriminator="kind")
]


class GraphExploreLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nodes: int = Field(default=2000, ge=1, le=5000)
    edges: int = Field(default=10000, ge=0, le=25000)


class GraphExploreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    scope: GraphExploreScope
    direction: Literal["any", "inbound", "outbound"] = "any"
    link_types: list[str] = Field(default_factory=list, max_length=100)
    target_types: list[str] = Field(default_factory=list, max_length=100)
    filters: list[GraphExploreFilter] = Field(default_factory=list, max_length=20)
    requested_limits: GraphExploreLimits = Field(default_factory=GraphExploreLimits)

    @model_validator(mode="after")
    def validate_item_budget(self):
        if isinstance(
            self.scope, GraphExploreItemScope
        ) and self.requested_limits.nodes < len(self.scope.items):
            raise ValueError("node limit must accommodate every requested item")
        return self


class GraphExploreScopeResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["items", "query"]
    anchor_ids: list[str]
    accessible_match_count: int = Field(ge=0)
    ranking: list[tuple[str, bool]] | None = None


class GraphExploreNode(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    root_type: str
    object_type: str
    role: Literal["anchor", "scope_match", "neighbor"]
    origin_ids: list[str]


class GraphExploreEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    source: str
    target: str
    type: str
    description: str
    count: int = Field(ge=0)


class GraphExploreBudget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    node_limit: int
    edge_limit: int
    returned_nodes: int
    returned_edges: int
    is_truncated: bool
    reasons: list[Literal["node_limit", "edge_limit"]]


class GraphExploreResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    scope: GraphExploreScopeResult
    nodes: list[GraphExploreNode]
    edges: list[GraphExploreEdge]
    budget: GraphExploreBudget


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
