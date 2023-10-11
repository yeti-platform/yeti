import datetime
from typing import Iterable

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from core.schemas import entity


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
