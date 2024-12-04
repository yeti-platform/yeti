from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, conlist

from core.schemas import audit, graph
from core.schemas.entity import Entity, EntityType, EntityTypes
from core.schemas.tag import MAX_TAGS_REQUEST


# Request schemas
class NewEntityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity: EntityTypes = Field(discriminator="type")
    tags: conlist(str, max_length=MAX_TAGS_REQUEST) = []


class PatchEntityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity: EntityTypes = Field(discriminator="type")


class EntitySearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: dict[str, str | int | list] = {}
    type: EntityType | None = None
    sorting: list[tuple[str, bool]] = []
    filter_aliases: list[tuple[str, str]] = []
    count: int = 50
    page: int = 0


class EntitySearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entities: list[EntityTypes]
    total: int


class EntityTagRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ids: list[str]
    tags: conlist(str, max_length=MAX_TAGS_REQUEST) = []
    strict: bool = False


class EntityTagResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tagged: int
    tags: dict[str, dict[str, graph.TagRelationship]]


# API endpoints
router = APIRouter()


@router.post("/")
def new(httpreq: Request, request: NewEntityRequest) -> EntityTypes:
    """Creates a new entity in the database."""
    new = request.entity.save()
    audit.log_timeline(httpreq.state.username, new)
    if request.tags:
        new.tag(request.tags)
    return new


@router.patch("/{entity_id}")
def patch(httpreq: Request, request: PatchEntityRequest, entity_id) -> EntityTypes:
    """Modifies entity in the database."""
    db_entity: EntityTypes = Entity.get(entity_id)
    if not db_entity:
        raise HTTPException(status_code=404, detail=f"Entity {entity_id} not found")
    if db_entity.type != request.entity.type:
        raise HTTPException(
            status_code=400,
            detail=f"Entity {entity_id} type mismatch. Provided '{request.entity.type}'. Expected '{db_entity.type}'",
        )
    update_data = request.entity.model_dump(exclude_unset=True)
    updated_entity = db_entity.model_copy(update=update_data)
    new = updated_entity.save()
    audit.log_timeline(httpreq.state.username, new, old=db_entity)
    return new


@router.get("/{entity_id}")
def details(entity_id) -> EntityTypes:
    """Returns details about an observable."""
    db_entity: EntityTypes = Entity.get(entity_id)  # type: ignore
    if not db_entity:
        raise HTTPException(status_code=404, detail=f"Entity {entity_id}  not found")
    db_entity.get_tags()
    return db_entity


@router.delete("/{entity_id}")
def delete(entity_id: str) -> None:
    """Deletes an Entity."""
    db_entity = Entity.get(entity_id)
    if not db_entity:
        raise HTTPException(status_code=404, detail="Entity ID {entity_id} not found")
    db_entity.delete()


@router.post("/search")
def search(request: EntitySearchRequest) -> EntitySearchResponse:
    """Searches for observables."""
    query = request.query
    tags = query.pop("tags", [])
    if request.type:
        query["type"] = request.type
    entities, total = Entity.filter(
        query_args=query,
        tag_filter=tags,
        offset=request.page * request.count,
        count=request.count,
        sorting=request.sorting,
        aliases=request.filter_aliases,
        links_count=True,
        graph_queries=[("tags", "tagged", "outbound", "name")],
    )
    response = EntitySearchResponse(entities=entities, total=total)
    return response


@router.post("/tag")
def tag(httpreq: Request, request: EntityTagRequest) -> EntityTagResponse:
    """Tags entities."""
    entities = []
    for entity_id in request.ids:
        db_entity = Entity.get(entity_id)
        if not db_entity:
            raise HTTPException(
                status_code=404,
                detail=f"Tagging request contained an unknown entity: ID:{entity_id}",
            )
        entities.append(db_entity)

    entity_tags = {}
    for db_entity in entities:
        old_tags = [tag[1].name for tag in db_entity.get_tags()]
        db_entity = db_entity.tag(request.tags, strict=request.strict)
        audit.log_timeline_tags(httpreq.state.username, db_entity, old_tags)
        entity_tags[db_entity.extended_id] = db_entity.tags

    return EntityTagResponse(tagged=len(entities), tags=entity_tags)
