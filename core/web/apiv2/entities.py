import datetime
from typing import Iterable

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from core.schemas import entity
from core.schemas import graph

# Request schemas
class NewEntityRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    entity: entity.EntityTypes


class PatchEntityRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    entity: entity.EntityTypes


class EntitySearchRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    name: str | None = None
    type: entity.EntityType | None = None
    count: int = 50
    page: int = 0


class EntitySearchResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    entities: list[entity.EntityTypes]
    total: int


class EntityTagRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    ids: list[str]
    tags: list[str]
    strict: bool = False


class EntityTagResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

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
    return new


@router.patch("/{entity_id}")
async def patch(request: PatchEntityRequest, entity_id) -> entity.EntityTypes:
    """Modifies entity in the database."""
    db_entity: entity.EntityTypes = entity.Entity.get(entity_id)  # type: ignore
    update_data = request.entity.model_dump(exclude_unset=True)
    updated_entity = db_entity.model_copy(update=update_data)
    new = updated_entity.save()
    return new


@router.get("/{entity_id}")
async def details(entity_id) -> entity.EntityTypes:
    """Returns details about an observable."""
    db_entity: entity.EntityTypes = entity.Entity.get(entity_id)  # type: ignore
    db_entity.get_tags()
    if not db_entity:
        raise HTTPException(status_code=404, detail="entity not found")
    return db_entity


@router.post("/search")
async def search(request: EntitySearchRequest) -> EntitySearchResponse:
    """Searches for observables."""
    request_args = request.model_dump()
    count = request_args.pop("count")
    page = request_args.pop("page")
    entities, total = entity.Entity.filter(
        request_args, offset=request.page * request.count, count=request.count
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
                detail=f"Tagging request contained an unknown entity: ID:{entity_id}")
        entities.append(db_entity)

    entity_tags = {}
    for db_entity in entities:
        db_entity.tag(request.tags, strict=request.strict)
        entity_tags[db_entity.extended_id] = db_entity.tags

    return EntityTagResponse(tagged=len(entities), tags=entity_tags)
