import datetime
from enum import Enum
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, ValidationInfo, conlist, model_validator
from pydantic.functional_validators import field_validator

from core.schemas import dfiq, entity, graph, indicator, observable, rbac, roles, tag
from core.schemas.graph import GraphFilter
from core.schemas.tag import MAX_TAGS_REQUEST

GRAPH_TYPE_MAPPINGS = {}  # type: dict[str, Type[entity.Entity] | Type[observable.Observable] | Type[indicator.Indicator]]
GRAPH_TYPE_MAPPINGS.update(observable.TYPE_MAPPING)
GRAPH_TYPE_MAPPINGS.update(entity.TYPE_MAPPING)
GRAPH_TYPE_MAPPINGS.update(indicator.TYPE_MAPPING)
GRAPH_TYPE_MAPPINGS.update(dfiq.TYPE_MAPPING)


def check_id_descriptor(value: str, info: ValidationInfo) -> str:
    if value.count("/") != 1:
        raise ValueError(
            f'{info.field_name} must describe the entity using using the "<type>/<id>" schema'
        )

    entity_type, _ = value.split("/")

    if entity_type not in GRAPH_TYPE_MAPPINGS:
        raise ValueError(
            f"{info.field_name} uses an invalid object type: {entity_type}"
        )

    return value


# Requequest schemas
class GraphDirection(str, Enum):
    outbound = "outbound"
    inbound = "inbound"
    any = "any"


class GraphSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    link_types: list[str] = []
    target_types: list[str] = []
    hops: int | None = None
    min_hops: int | None = None
    max_hops: int | None = None
    graph: str
    direction: GraphDirection
    filter: list[GraphFilter] = []
    include_original: bool
    count: int = 50
    page: int = 0
    sorting: list[tuple[str, bool]] = []

    @field_validator("source")
    @classmethod
    def check_id_descriptor(cls, value: str, info: ValidationInfo) -> str:
        return check_id_descriptor(value, info)

    @model_validator(mode="before")
    @classmethod
    def validate_hops(cls, data: Any):
        hops = data.get("hops")
        min_hops = data.get("min_hops")
        max_hops = data.get("max_hops")

        if all(x is None for x in [hops, min_hops, max_hops]):
            raise ValueError("hops, min_hops, or max_hops must be provided")

        if hops is not None:
            if min_hops is not None or max_hops is not None:
                raise ValueError("hops cannot be used with min_hops or max_hops")
        elif min_hops is not None or max_hops is not None:
            if min_hops is None or max_hops is None:
                raise ValueError("min_hops and max_hops must be used together")
            if min_hops > max_hops:
                raise ValueError("min_hops must be less than or equal to max_hops")

        if hops is not None and hops < 1:
            raise ValueError("hops must be greater than 0")
        if min_hops is not None and min_hops < 1:
            raise ValueError("min_hops must be greater than 0")
        if max_hops is not None and max_hops < 1:
            raise ValueError("max_hops must be greater than 0")

        return data


class GraphAddRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    target: str
    link_type: str
    description: str

    @field_validator("source", "target")
    @classmethod
    def check_entity_descriptor(cls, value: str, info: ValidationInfo) -> str:
        return check_id_descriptor(value, info)


class GraphPatchRequest(BaseModel):
    link_type: str
    description: str


class GraphSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vertices: dict[
        str,
        observable.ObservableTypes
        | entity.EntityTypes
        | indicator.IndicatorTypes
        | tag.Tag
        | dfiq.DFIQTypes,
    ]
    paths: list[list[graph.Relationship]]
    total: int


# API endpoints
router = APIRouter()


@router.post("/search")
def search(httpreq: Request, request: GraphSearchRequest) -> GraphSearchResponse:
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
        filter=request.filter,
        include_original=request.include_original,
        graph=request.graph,
        min_hops=request.min_hops or request.hops,
        max_hops=request.max_hops or request.hops,
        count=request.count,
        offset=request.page * request.count,
        sorting=request.sorting,
        user=httpreq.state.user,
    )
    return GraphSearchResponse(vertices=vertices, paths=paths, total=total)


@router.post("/add")
@rbac.global_permission(roles.Permission.WRITE)
def add(httpreq: Request, request: GraphAddRequest) -> graph.Relationship:
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


@router.patch("/{relationship_id}")
@rbac.global_permission(roles.Permission.WRITE)
def edit(
    httpreq: Request, relationship_id: str, request: GraphPatchRequest
) -> graph.Relationship:
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


@router.post("/{relationship_id}/swap")
@rbac.global_permission(roles.Permission.WRITE)
def swap(httpreq: Request, relationship_id: str) -> graph.Relationship:
    """Swaps the source and target of a relationship."""
    relationship = graph.Relationship.get(relationship_id)
    if relationship is None:
        raise HTTPException(
            status_code=404, detail=f"Relationship {relationship_id} not found"
        )
    relationship.swap_link()
    return relationship


@router.delete("/{relationship_id}")
@rbac.global_permission(roles.Permission.WRITE)
def delete(httpreq: Request, relationship_id: str) -> None:
    """Deletes a link from the graph."""
    relationship = graph.Relationship.get(relationship_id)
    if relationship is None:
        raise HTTPException(
            status_code=404, detail=f"Relationship {relationship_id} not found"
        )
    relationship.delete()


class AnalysisRequest(BaseModel):
    observables: list[str]
    add_tags: conlist(str, max_length=MAX_TAGS_REQUEST) = []
    regex_match: bool = False
    add_type: observable.ObservableType | None = None
    fetch_neighbors: bool = True
    add_unknown: bool = False


class AnalysisResponse(BaseModel):
    entities: list[tuple[graph.Relationship, entity.EntityTypes]]
    observables: list[tuple[graph.Relationship, observable.ObservableTypes]]
    known: list[observable.ObservableTypes]
    matches: list[tuple[str, indicator.IndicatorTypes]]  # IndicatorMatch?
    unknown: set[str]


@router.post("/match")
def match(httpreq: Request, request: AnalysisRequest) -> AnalysisResponse:
    """Fetches neighbors for a given Yeti Object."""

    entities = []  # type: list[tuple[graph.Relationship, entity.Entity]]
    seen_entities = set()
    observables = []  # type: list[tuple[graph.Relationship, observable.Observable]]

    unknown = set(request.observables)
    known = {}  # type: dict[str, observable.Observable]
    if request.add_unknown and httpreq.state.user.has_global_role(
        roles.Permission.WRITE
    ):
        for value in request.observables:
            try:
                observable.save(
                    tags=request.add_tags, value=value, type=request.add_type
                )
            except ValueError:
                continue
            unknown.discard(value)

    operator = "value__in"
    if request.regex_match:
        operator = "value__in~"
    db_observables, _ = observable.Observable.filter(
        query_args={operator: request.observables},
        wildcard=False,
        user=httpreq.state.user,
    )
    for db_observable in db_observables:
        known[db_observable.value] = db_observable
        unknown.discard(db_observable.value)
        processed_relationships = set()

        if request.fetch_neighbors:
            vertices, paths, _ = db_observable.neighbors(user=httpreq.state.user)
            for path in paths:
                edge = path[0]  # neighbors only returns 1 hop max by default
                if edge.id in processed_relationships:
                    continue

                if edge.target == db_observable.extended_id:
                    other = vertices[edge.source]
                else:
                    other = vertices[edge.target]

                if isinstance(other, entity.Entity):
                    if other.extended_id in seen_entities:
                        continue
                    entities.append((edge, other))
                    seen_entities.add(other.extended_id)
                if isinstance(other, observable.Observable):
                    observables.append((edge, other))

                processed_relationships.add(edge.id)

    matches = []
    for observable_string, indi in indicator.Regex.search(request.observables):
        matches.append((observable_string, indi))

    return AnalysisResponse(
        entities=entities,
        observables=observables,
        unknown=unknown,
        matches=matches,
        known=list(known.values()),
    )
