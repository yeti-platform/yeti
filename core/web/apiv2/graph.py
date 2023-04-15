from enum import Enum
from typing import Type

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.schemas import entity, observable
from core.schemas.graph import Relationship
from core.schemas.indicator import Indicator

GRAPH_TYPE_MAPPINGS = {} # type: dict[str, Type[entity.Entity] | Type[observable.Observable]]
GRAPH_TYPE_MAPPINGS.update(observable.TYPE_MAPPING)
GRAPH_TYPE_MAPPINGS.update(entity.TYPE_MAPPING)


# Requequest schemas

class GraphDirection(str, Enum):
    outbound = 'outbound'
    inbound = 'inbound'
    any = 'any'

#TODO: #761 Add Pagination to GraphSearchRequest
class GraphSearchRequest(BaseModel):
    source: str
    link_types: list[str] = []
    target_types: list[str] = []
    hops: int
    direction: GraphDirection
    include_original: bool
    count: int = 50
    page: int = 0

class GraphAddRequest(BaseModel):
    source: str
    target: str
    link_type: str
    description: str

class GraphSearchResponse(BaseModel):
    vertices: dict[str, observable.Observable | entity.Entity]
    edges: list[Relationship]
    count: int


# API endpoints
router = APIRouter()

@router.post('/search')
async def search(request: GraphSearchRequest) -> GraphSearchResponse:
    """Fetches neighbros for a given Yeti Object."""
    object_type, object_id = request.source.split('/')
    if object_type not in GRAPH_TYPE_MAPPINGS:
        raise HTTPException(status_code=400, detail='Invalid object type')
    yeti_object = GRAPH_TYPE_MAPPINGS[object_type].get(object_id)
    if not yeti_object:
        raise HTTPException(
            status_code=404, detail=f'Source object {request.source} not found')
    vertices, edges, count = yeti_object.neighbors(
        link_types=request.link_types,
        target_types=request.target_types,
        direction=request.direction,
        include_original=request.include_original,
        hops=request.hops,
        count=request.count,
        offset=request.page
    )
    return GraphSearchResponse(vertices=vertices, edges=edges, count=count)

@router.post('/add')
async def add(request: GraphAddRequest) -> Relationship:
    """Adds a link to the graph."""
    source_type, source_id = request.source.split('/')
    target_type, target_id = request.target.split('/')

    if source_type not in GRAPH_TYPE_MAPPINGS:
        raise HTTPException(
            status_code=400,
            detail=f'Invalid source object type: {source_type}')
    if target_type not in GRAPH_TYPE_MAPPINGS:
        raise HTTPException(
            status_code=400,
            detail=f'Invalid target object type: {target_type}')

    source_object = GRAPH_TYPE_MAPPINGS[source_type].get(source_id)
    target_object = GRAPH_TYPE_MAPPINGS[target_type].get(target_id)
    if source_object is None:
        raise HTTPException(
            status_code=404,
            detail=f'Source object {request.source} not found')
    if target_object is None:
        raise HTTPException(
            status_code=404,
            detail=f'Target object {request.target} not found')

    relationship = source_object.link_to(
        target_object, request.link_type, request.description)
    return relationship

@router.delete('/{relationship_id}')
async def delete(relationship_id: str) -> None:
    """Deletes a link from the graph."""
    relationship = Relationship.get(relationship_id)
    if relationship is None:
        raise HTTPException(
            status_code=404,
            detail=f'Relationship {relationship_id} not found')
    relationship.delete()


class AnalysisRequest(BaseModel):
    observables: list[str]
    add_tags: list[str] = []
    fetch_neighbors: bool = True
    add_unknown: bool = False

class AnalysisResponse(BaseModel):
    entities: list[tuple[Relationship, entity.Entity]]
    observables: list[tuple[Relationship, observable.Observable]]
    known: list[observable.Observable]
    matches: list[tuple[str, Indicator]]  # IndicatorMatch?
    unknown: set[str]


@router.post('/match')
async def match(request: AnalysisRequest) -> AnalysisResponse:
    """Fetches neighbors for a given Yeti Object."""

    entities = []  # type: list[tuple[Relationship, entity.Entity]]
    observables = []  # type: list[tuple[Relationship, observable.Observable]]

    unknown = set(request.observables)
    known = {}  # type: dict[str, observable.Observable]
    if request.add_unknown:
        for value in request.observables:
            try:
                observable.Observable.add_text(value, tags=request.add_tags)
                unknown.discard(value)
            except ValueError:
                pass

    for db_observable in observable.Observable.filter(args={"value__in": request.observables}):
        known[db_observable.value] = db_observable
        unknown.discard(db_observable.value)
        processed_relationships = set()

        if request.fetch_neighbors:
            vertices, edges, _ = db_observable.neighbors()
            # Get neighboring entities and relationships.
            for edge in edges:
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
    for observable_string, indicator in Indicator.search(request.observables):
        matches.append((observable_string, indicator))

    return AnalysisResponse(
        entities=entities,
        observables=observables,
        unknown=unknown,
        matches=matches,
        known=list(known.values()),
    )
