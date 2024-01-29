from typing import Iterable

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from core.schemas import entity, graph


# Request schemas
class NewEntityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity: entity.EntityTypes
    tags: list[str] = []


class PatchEntityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity: entity.EntityTypes


class EntitySearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: dict[str, str | int | list] = {}
    type: entity.EntityType | None = None
    count: int = 50
    page: int = 0


class EntitySearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entities: list[entity.EntityTypes]
    total: int


class EntityTagRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ids: list[str]
    tags: list[str]
    strict: bool = False


class EntityTagResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tagged: int
    tags: dict[str, dict[str, graph.TagRelationship]]


# API endpoints
router = APIRouter()


@router.get("/")
async def entities_root() -> Iterable[entity.EntityTypes]:
    return entity.Entity.list()


@router.post("/")
async def new(request: NewEntityRequest) -> entity.EntityTypes:
    """Creates a new entity in the database."""
    new = request.entity.save()
    if request.tags:
        new.tag(request.tags)
    return new


@router.patch("/{entity_id}")
async def patch(request: PatchEntityRequest, entity_id) -> entity.EntityTypes:
    """Modifies entity in the database."""
    db_entity: entity.EntityTypes = entity.Entity.get(entity_id)
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
async def details(entity_id) -> entity.EntityTypes:
    """Returns details about an observable."""
    db_entity: entity.EntityTypes = entity.Entity.get(entity_id)  # type: ignore
    if not db_entity:
        raise HTTPException(status_code=404, detail=f"Entity {entity_id}  not found")
    db_entity.get_tags()
    return db_entity


@router.delete("/{entity_id}")
async def delete(entity_id: str) -> None:
    """Deletes an Entity."""
    db_entity = entity.Entity.get(entity_id)
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
    entities, total = entity.Entity.filter(
        query,
        tag_filter=tags,
        offset=request.page * request.count,
        count=request.count,
        graph_queries=[("tags", "tagged", "outbound", "name")],
    )
    return EntitySearchResponse(entities=entities, total=total)


@router.post("/tag")
async def tag(request: EntityTagRequest) -> EntityTagResponse:
    """Tags entities."""
    entities = []
    for entity_id in request.ids:
        db_entity = entity.Entity.get(entity_id)
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
