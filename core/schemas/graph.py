import datetime
from enum import Enum

from core.helpers import refang, REGEXES

from pydantic import BaseModel
from core import database_arango
from core.schemas.observable import Observable

# Database model
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


# Graph API
class GraphDirection(str, Enum):
    outbound = 'outbound'
    inbound = 'inbound'
    any = 'any'

class GraphSearchRequest(BaseModel):
    source: str
    link_type: str | None
    hops: int
    direction: GraphDirection
    include_original: bool

class GraphSearchResponse(BaseModel):
    vertices: dict[str, Observable]
    edges: list[Relationship]
