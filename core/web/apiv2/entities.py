from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, conlist

from core.schemas import audit, model, rbac, roles
from core.schemas.entity import Entity, EntityType, EntityTypes
from core.schemas.tag import MAX_TAGS_REQUEST

from . import context


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
    tags: dict[str, dict[str, model.YetiTagInstance]]


# API endpoints
router = APIRouter()


@router.post("/")
@rbac.global_permission(roles.Permission.WRITE)
def new(httpreq: Request, request: NewEntityRequest) -> EntityTypes:
    """Creates a new entity in the database."""
    new = request.entity.save()
    rbac.set_acls(new, user=httpreq.state.user)
    audit.log_timeline(httpreq.state.username, new)
    if request.tags:
        new.tag(request.tags)
    return new


@router.patch("/{id}")
@rbac.permission_on_target(roles.Permission.WRITE)
def patch(httpreq: Request, request: PatchEntityRequest, id: str) -> EntityTypes:
    """Modifies entity in the database."""
    db_entity: EntityTypes = Entity.get(id)
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
) -> EntityTypes:
    """Adds context to an Entity."""
    return context.add_context(Entity, httpreq, id, request)


@router.put("/{id}/context")
@rbac.permission_on_target(roles.Permission.WRITE)
def replace_context(
    httpreq: Request, id: str, request: context.ReplaceContextRequest
) -> EntityTypes:
    """Replaces context in an Entity."""
    return context.replace_context(Entity, httpreq, id, request)


@router.post("/{id}/context/delete")
@rbac.permission_on_target(roles.Permission.WRITE)
def delete_context(
    httpreq: Request, id, request: context.DeleteContextRequest
) -> EntityTypes:
    """Removes context to an Entity."""
    return context.delete_context(Entity, httpreq, id, request)


@router.get("/")
def get(
    httpreq: Request,
    name: str,
    type: EntityType | None = None,
) -> EntityTypes:
    """Gets an entity by name."""

    params = {"name": name}
    if type:
        params["type"] = type

    entity = Entity.find(**params)
    if not entity:
        raise HTTPException(
            status_code=404,
            detail=f"Entity {name} not found (type: {type or 'any'})",
        )
    entity.get_tags()
    if not rbac.RBAC_ENABLED or httpreq.state.user.admin:
        return entity
    if not httpreq.state.user.has_permissions(
        entity.extended_id, roles.Permission.READ
    ):
        raise HTTPException(
            status_code=403,
            detail=f"Forbidden: missing privileges {roles.Permission.READ} on target {entity.extended_id}",
        )
    return entity


@router.get("/{id}")
@rbac.permission_on_target(roles.Permission.READ)
def details(httpreq: Request, id: str) -> EntityTypes:
    """Returns details about an observable."""
    db_entity: EntityTypes = Entity.get(id)  # type: ignore
    if not db_entity:
        raise HTTPException(status_code=404, detail=f"Entity {id} not found")
    db_entity.get_tags()
    db_entity.get_acls()
    return db_entity


@router.delete("/{id}")
@rbac.permission_on_target(roles.Permission.DELETE)
def delete(httpreq: Request, id: str) -> None:
    """Deletes an Entity."""
    db_entity = Entity.get(id)
    if not db_entity:
        raise HTTPException(status_code=404, detail=f"Entity ID {id} not found")
    audit.log_timeline(httpreq.state.username, db_entity, action="delete")
    db_entity.delete()


@router.post("/search")
def search(httpreq: Request, request: EntitySearchRequest) -> EntitySearchResponse:
    """Searches for observables."""
    query = request.query
    if request.type:
        query["type"] = request.type
    entities, total = Entity.filter(
        query_args=query,
        offset=request.page * request.count,
        count=request.count,
        sorting=request.sorting,
        aliases=request.filter_aliases,
        links_count=True,
        user=httpreq.state.user,
    )
    response = EntitySearchResponse(entities=entities, total=total)
    return response


@router.post("/tag")
@rbac.permission_on_ids(roles.Permission.WRITE)
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
        old_tags = [tag.name for tag in db_entity.get_tags().values()]
        db_entity = db_entity.tag(request.tags, strict=request.strict)
        audit.log_timeline_tags(httpreq.state.username, db_entity, old_tags)
        entity_tags[db_entity.extended_id] = {tag.name: tag for tag in db_entity.tags}

    return EntityTagResponse(tagged=len(entities), tags=entity_tags)
