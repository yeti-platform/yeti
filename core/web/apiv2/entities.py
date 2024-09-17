from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, conlist

from core.schemas import graph
from core.schemas.entity import Entity, EntityType, EntityTypes
from core.schemas.tag import MAX_TAGS_REQUEST


# Request schemas
class NewEntityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity: EntityTypes
    tags: conlist(str, max_length=MAX_TAGS_REQUEST) = []


class PatchEntityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity: EntityTypes


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
async def new(request: NewEntityRequest) -> EntityTypes:
    """Creates a new entity in the database."""
    new = request.entity.save()
    if request.tags:
        new.tag(request.tags)
    return new


@router.patch("/{entity_id}")
async def patch(request: PatchEntityRequest, entity_id) -> EntityTypes:
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
    return new


@router.get("/{entity_id}")
async def details(entity_id) -> EntityTypes:
    """Returns details about an observable."""
    db_entity: EntityTypes = Entity.get(entity_id)  # type: ignore
    if not db_entity:
        raise HTTPException(status_code=404, detail=f"Entity {entity_id}  not found")
    db_entity.get_tags()
    return db_entity


@router.delete("/{entity_id}")
async def delete(entity_id: str) -> None:
    """Deletes an Entity."""
    db_entity = Entity.get(entity_id)
    if not db_entity:
        raise HTTPException(status_code=404, detail="Entity ID {entity_id} not found")
    db_entity.delete()


@router.post("/search")
async def search(request: EntitySearchRequest) -> EntitySearchResponse:
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
        graph_queries=[("tags", "tagged", "outbound", "name")],
    )
    return EntitySearchResponse(entities=entities, total=total)


@router.post("/tag")
async def tag(request: EntityTagRequest) -> EntityTagResponse:
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
        db_entity.tag(request.tags, strict=request.strict)
        entity_tags[db_entity.extended_id] = db_entity.tags

    return EntityTagResponse(tagged=len(entities), tags=entity_tags)
