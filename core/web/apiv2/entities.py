from typing import Annotated

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from core.schemas import audit, model, rbac, roles
from core.schemas.entity import Entity, EntityType, EntityTypesRuntime
from core.schemas.tag import MAX_TAGS_REQUEST

from . import context, crud, tagging


# Request schemas
class NewEntityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity: EntityTypesRuntime = Field(discriminator="type")
    tags: Annotated[list[str], Field(max_length=MAX_TAGS_REQUEST)] = []


class PatchEntityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entity: EntityTypesRuntime = Field(discriminator="type")


class EntitySearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: dict[str, str | int | list] = {}
    type: EntityType | None = None
    sorting: list[tuple[str, bool]] = []
    filter_aliases: list[tuple[str, str]] = []
    count: int = 50
    page: int = 0


class EntityMultipleGetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    names: list[str] = []
    type: EntityType | None = None
    sorting: list[tuple[str, bool]] = []
    filter_aliases: list[tuple[str, str]] = []
    count: int = 50
    page: int = 0


class EntitySearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entities: list[EntityTypesRuntime]
    total: int


class EntityTagRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ids: list[str]
    tags: Annotated[list[str], Field(max_length=MAX_TAGS_REQUEST)] = []
    strict: bool = False


class EntityTagResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tagged: int
    tags: dict[str, dict[str, model.YetiTagInstance]]


# API endpoints
router = APIRouter()


@router.post("/")
@rbac.global_permission(roles.Permission.WRITE)
def new(httpreq: Request, request: NewEntityRequest) -> EntityTypesRuntime:
    """Creates a new entity in the database."""
    new = request.entity.save()
    rbac.set_acls(new, user=httpreq.state.user)
    audit.log_timeline(httpreq.state.username, new)
    if request.tags:
        new.tag(request.tags)
    return new


@router.patch("/{id}")
@rbac.permission_on_target(roles.Permission.WRITE)
def patch(httpreq: Request, request: PatchEntityRequest, id: str) -> EntityTypesRuntime:
    """Modifies entity in the database."""
    db_entity = Entity.get(id)
    if not db_entity:
        raise HTTPException(status_code=404, detail=f"Entity {id} not found")
    if db_entity.type != request.entity.type:
        raise HTTPException(
            status_code=400,
            detail=f"Entity {id} type mismatch. Provided '{request.entity.type}'. Expected '{db_entity.type}'",
        )
    db_entity.get_tags()
    update_data = request.entity.model_dump(exclude_unset=True)
    updated_entity = db_entity.model_copy(update=update_data)
    new = updated_entity.save()
    audit.log_timeline(httpreq.state.username, new, old=db_entity)
    return new


@router.post("/{id}/context")
@rbac.permission_on_target(roles.Permission.WRITE)
def add_context(
    httpreq: Request, id: str, request: context.AddContextRequest
) -> EntityTypesRuntime:
    """Adds context to an Entity."""
    return context.add_context(Entity, httpreq, id, request)


@router.put("/{id}/context")
@rbac.permission_on_target(roles.Permission.WRITE)
def replace_context(
    httpreq: Request, id: str, request: context.ReplaceContextRequest
) -> EntityTypesRuntime:
    """Replaces context in an Entity."""
    return context.replace_context(Entity, httpreq, id, request)


@router.post("/{id}/context/delete")
@rbac.permission_on_target(roles.Permission.WRITE)
def delete_context(
    httpreq: Request, id, request: context.DeleteContextRequest
) -> EntityTypesRuntime:
    """Removes context to an Entity."""
    return context.delete_context(Entity, httpreq, id, request)


@router.get("/")
def get(
    httpreq: Request,
    name: str,
    type: EntityType | None = None,
) -> EntityTypesRuntime:
    """Gets an entity by name."""
    params = {"name": name}
    if type:
        params["type"] = type
    return crud.get_by_lookup(
        Entity, httpreq, params, f"Entity {name} not found (type: {type or 'any'})"
    )


@router.get("/{id}")
@rbac.permission_on_target(roles.Permission.READ)
def details(httpreq: Request, id: str) -> EntityTypesRuntime:
    """Returns details about an observable."""
    return crud.get_details(Entity, id, f"Entity {id} not found")


@router.delete("/{id}")
@rbac.permission_on_target(roles.Permission.DELETE)
def delete(httpreq: Request, id: str) -> None:
    """Deletes an Entity."""
    crud.delete_object(Entity, httpreq, id, f"Entity ID {id} not found")


@router.post("/search")
def search(httpreq: Request, request: EntitySearchRequest) -> EntitySearchResponse:
    """Searches for observables."""
    entities, total = crud.search_objects(
        Entity,
        httpreq,
        request.query,
        request.type,
        request.sorting,
        request.count,
        request.page,
        aliases=request.filter_aliases,
        links_count=True,
    )
    return EntitySearchResponse(entities=entities, total=total)


@router.post("/get/multiple")
def get_multiple(
    httpreq: Request, request: EntityMultipleGetRequest
) -> EntitySearchResponse:
    """Gets multiple entities by name."""
    entities, total = crud.search_objects(
        Entity,
        httpreq,
        {"name__in": request.names},
        request.type,
        request.sorting,
        request.count,
        request.page,
        aliases=request.filter_aliases,
        links_count=True,
    )
    return EntitySearchResponse(entities=entities, total=total)


@router.post("/tag")
@rbac.permission_on_ids(roles.Permission.WRITE)
def tag(httpreq: Request, request: EntityTagRequest) -> EntityTagResponse:
    """Tags entities."""
    tagged, tags = tagging.tag_objects(
        Entity,
        httpreq,
        request.ids,
        request.tags,
        request.strict,
        not_found_status_code=404,
        not_found_detail=(
            lambda eid: f"Tagging request contained an unknown entity: ID:{eid}"
        ),
    )
    return EntityTagResponse(tagged=tagged, tags=tags)
