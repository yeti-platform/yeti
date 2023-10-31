import datetime
from enum import Enum

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, ValidationInfo
from pydantic.functional_validators import field_validator

from core.schemas import entity, graph, indicator, observable, tag

GRAPH_TYPE_MAPPINGS = (
    {}
)  # type: dict[str, Type[entity.Entity] | Type[observable.Observable] | Type[indicator.Indicator]]
GRAPH_TYPE_MAPPINGS.update(observable.TYPE_MAPPING)
GRAPH_TYPE_MAPPINGS.update(entity.TYPE_MAPPING)
GRAPH_TYPE_MAPPINGS.update(indicator.TYPE_MAPPING)


# Requequest schemas
class GraphDirection(str, Enum):
    outbound = "outbound"
    inbound = "inbound"
    any = "any"


class GraphSearchRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    source: str
    link_types: list[str] = []
    target_types: list[str] = []
    hops: int
    graph: str
    direction: GraphDirection
    include_original: bool
    count: int = 50
    page: int = 0


class GraphAddRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    source: str
    target: str
    link_type: str
    description: str

    @field_validator('source', 'target')
    @classmethod
    def check_entity_descriptor(cls, value: str, info: ValidationInfo) -> str:
        if value.count("/") != 1:
            raise ValueError(f'{info.field_name} must describe the entity using using the "<type>/<id>" schema')

        entity_type, _ = value.split("/")

        if entity_type not in GRAPH_TYPE_MAPPINGS:
            raise ValueError(f'{info.field_name} uses an invalid object type: {entity_type}')

        return value


class GraphPatchRequest(BaseModel):
    link_type: str
    description: str


class GraphSearchResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    vertices: dict[str, observable.Observable | entity.Entity | indicator.Indicator | tag.Tag]
    paths: list[list[graph.Relationship | graph.TagRelationship]]
    total: int


# API endpoints
router = APIRouter()


@router.post("/search")
async def search(request: GraphSearchRequest) -> GraphSearchResponse:
    """Fetches neighbros for a given Yeti Object."""
    object_type, object_id = request.source.split("/")
    if object_type not in GRAPH_TYPE_MAPPINGS:
        raise HTTPException(
            status_code=400, detail=f"Invalid object type: {object_type}"
        )
    yeti_object = GRAPH_TYPE_MAPPINGS[object_type].get(object_id)
    if not yeti_object:
        raise HTTPException(
            status_code=404, detail=f"Source object {request.source} not found"
        )
    vertices, paths, total = yeti_object.neighbors(
        link_types=request.link_types,
        target_types=request.target_types,
        direction=request.direction,
        include_original=request.include_original,
        graph=request.graph,
        hops=request.hops,
        count=request.count,
        offset=request.page,
    )
    return GraphSearchResponse(vertices=vertices, paths=paths, total=total)


@router.post("/add")
async def add(request: GraphAddRequest) -> graph.Relationship:
    """Adds a link to the graph."""
    source_type, source_id = request.source.split("/")
    target_type, target_id = request.target.split("/")

    source_object = GRAPH_TYPE_MAPPINGS[source_type].get(source_id)
    target_object = GRAPH_TYPE_MAPPINGS[target_type].get(target_id)
    if source_object is None:
        raise HTTPException(
            status_code=404, detail=f"Source object {request.source} not found"
        )
    if target_object is None:
        raise HTTPException(
            status_code=404, detail=f"Target object {request.target} not found"
        )

    relationship = source_object.link_to(
        target_object, request.link_type, request.description
    )
    return relationship

@router.patch('/{relationship_id}')
async def edit(relationship_id: str, request: GraphPatchRequest) -> graph.Relationship:
    """Edits a Relationship in the graph."""
    relationship = graph.Relationship.get(relationship_id)
    if relationship is None:
        raise HTTPException(
            status_code=404, detail=f"Relationship {relationship_id} not found"
        )

    relationship.description = request.description
    relationship.type = request.link_type
    relationship.modified = datetime.datetime.now(datetime.timezone.utc)

    return relationship.save()


@router.delete("/{relationship_id}")
async def delete(relationship_id: str) -> None:
    """Deletes a link from the graph."""
    relationship = graph.Relationship.get(relationship_id)
    if relationship is None:
        raise HTTPException(
            status_code=404, detail=f"Relationship {relationship_id} not found"
        )
    relationship.delete()


class AnalysisRequest(BaseModel):
    observables: list[str]
    add_tags: list[str] = []
    fetch_neighbors: bool = True
    add_unknown: bool = False


class AnalysisResponse(BaseModel):
    entities: list[tuple[graph.Relationship, entity.Entity]]
    observables: list[tuple[graph.Relationship, observable.Observable]]
    known: list[observable.Observable]
    matches: list[tuple[str, indicator.Indicator]]  # IndicatorMatch?
    unknown: set[str]


@router.post("/match")
async def match(request: AnalysisRequest) -> AnalysisResponse:
    """Fetches neighbors for a given Yeti Object."""

    entities = []  # type: list[tuple[graph.Relationship, entity.Entity]]
    observables = []  # type: list[tuple[graph.Relationship, observable.Observable]]

    unknown = set(request.observables)
    known = {}  # type: dict[str, observable.Observable]
    if request.add_unknown:
        for value in request.observables:
            try:
                observable.Observable.add_text(value, tags=request.add_tags)
                unknown.discard(value)
            except ValueError:
                pass
    db_observables, _ = observable.Observable.filter(
        query_args={"value__in": request.observables}
    )
    for db_observable in db_observables:
        known[db_observable.value] = db_observable
        unknown.discard(db_observable.value)
        processed_relationships = set()

        if request.fetch_neighbors:
            vertices, paths, _ = db_observable.neighbors()
            for path in paths:
                edge = path[0]  # neighbors only returns 1 hop max by default
                if edge.id in processed_relationships:
                    continue

                if edge.target == db_observable.extended_id:
                    other = vertices[edge.source]
                else:
                    other = vertices[edge.target]

                if isinstance(other, entity.Entity):
                    entities.append((edge, other))
                if isinstance(other, observable.Observable):
                    observables.append((edge, other))

                processed_relationships.add(edge.id)

    matches = []
    for observable_string, indi in indicator.Indicator.search(request.observables):
        matches.append((observable_string, indi))

    return AnalysisResponse(
        entities=entities,
        observables=observables,
        unknown=unknown,
        matches=matches,
        known=list(known.values()),
    )
