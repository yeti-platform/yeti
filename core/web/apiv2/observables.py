from typing import Annotated, Iterable, List

import validators
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, ConfigDict, Field, conlist, field_validator

from core.config.config import yeti_config
from core.schemas import audit, graph, observable, roles
from core.schemas.observable import Observable, ObservableType, ObservableTypes
from core.schemas.rbac import global_permission, permission_on_ids, permission_on_target
from core.schemas.tag import MAX_TAG_LENGTH, MAX_TAGS_REQUEST

# defaults to 10MiB if not defined
MAX_FILE_UPLOAD = yeti_config.get("web", "max_file_upload", 10 * 1024 * 1024)


class TagRequestMixin(BaseModel):
    tags: conlist(str, max_length=MAX_TAGS_REQUEST) = []

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, value) -> list[str]:
        for tag in value:
            if not tag or not tag.strip():
                raise ValueError("Tags cannot be empty")
            if len(tag) > MAX_TAG_LENGTH:
                raise ValueError(f"Tag {tag} exceeds max length ({MAX_TAG_LENGTH})")
        return value


# Request schemas
class NewObservableRequest(TagRequestMixin):
    model_config = ConfigDict(extra="forbid")

    value: str
    type: ObservableType


class NewExtendedObservableRequest(TagRequestMixin):
    model_config = ConfigDict(extra="forbid")

    observable: ObservableTypes = Field(discriminant="type")


class PatchObservableRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observable: ObservableTypes = Field(discriminant="type")


class NewBulkObservableAddRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observables: list[NewObservableRequest]


class BulkObservableAddResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    added: list[ObservableTypes] = []
    failed: list[str] = []


class ImportTextRequest(TagRequestMixin):
    model_config = ConfigDict(extra="forbid")

    text: str


AddTextRequest = ImportTextRequest


class ImportUrlRequest(TagRequestMixin):
    model_config = ConfigDict(extra="forbid")

    url: str


class AddContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    context: dict
    skip_compare: set = set()


class DeleteContextRequest(AddContextRequest):
    pass


class ObservableSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: dict[str, str | int | list] = {}
    type: ObservableType | None = None
    sorting: list[tuple[str, bool]] = []
    count: int = 50
    page: int = 0


class ObservableSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observables: list[ObservableTypes]
    total: int


class ObservableTagRequest(TagRequestMixin):
    model_config = ConfigDict(extra="forbid")

    ids: list[str]
    strict: bool = False


class ObservableTagResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tagged: int
    tags: dict[str, dict[str, graph.TagRelationship]]


# API endpoints
router = APIRouter()


@router.post("/")
@global_permission(roles.Permission.WRITE)
def new(httpreq: Request, request: NewObservableRequest) -> ObservableTypes:
    """Creates a new observable in the database.

    Raises:
        HTTPException(400) if observable already exists.
    """
    if observable.find(value=request.value, type=request.type):
        raise HTTPException(
            status_code=400,
            detail=f"Observable with value {request.value} already exists",
        )
    try:
        new = observable.save(type=request.type, value=request.value, tags=request.tags)
        audit.log_timeline(httpreq.state.username, new)
        httpreq.state.user.link_to_acl(new, roles.Role.OWNER)

        return new
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Failed to add observable",
        )


@router.post("/extended")
@global_permission(roles.Permission.WRITE)
def new_extended(
    httpreq: Request, request: NewExtendedObservableRequest
) -> ObservableTypes:
    """Creates a new observable in the database with extended properties.

    Raises:
        HTTPException(400) if observable already exists.
    """
    if observable.find(value=request.observable.value, type=request.observable.type):
        raise HTTPException(
            status_code=400,
            detail=f"Observable with value {request.observable.value} already exists",
        )
    try:
        new = observable.save(
            **request.observable.model_dump(exclude={"tags"}), tags=request.tags
        )
        audit.log_timeline(httpreq.state.username, new)
        httpreq.state.user.link_to_acl(new, roles.Role.OWNER)
        return new
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Failed to add observable",
        )


@router.patch("/{id}")
@permission_on_target(roles.Permission.WRITE)
def patch(httpreq: Request, request: PatchObservableRequest, id) -> ObservableTypes:
    """Modifies observable in the database."""
    db_observable = Observable.get(id)
    if not db_observable:
        raise HTTPException(status_code=404, detail=f"Observable {id} not found")
    if db_observable.type != request.observable.type:
        raise HTTPException(
            status_code=400,
            detail=f"Observable {id} type mismatch. Provided '{request.observable.type}'. Expected '{db_observable.type}'",
        )
    db_observable.get_tags()
    update_data = request.observable.model_dump(exclude_unset=True)
    updated_observable = db_observable.model_copy(update=update_data)
    new = updated_observable.save()
    new.get_acls(httpreq.state.user)
    audit.log_timeline(httpreq.state.username, new, old=db_observable)
    return new


@router.post("/bulk")
@global_permission(roles.Permission.WRITE)
def bulk_add(
    httpreq: Request, request: NewBulkObservableAddRequest
) -> BulkObservableAddResponse:
    """Bulk-creates new observables in the database."""
    response = BulkObservableAddResponse()
    for new_observable in request.observables:
        try:
            observable_obj = observable.save(
                type=new_observable.type,
                value=new_observable.value,
                tags=new_observable.tags,
            )
            audit.log_timeline(httpreq.state.username, observable_obj)
            httpreq.state.user.link_to_acl(observable_obj, roles.Role.OWNER)
        except (ValueError, RuntimeError):
            response.failed.append(new_observable.value)
            continue
        response.added.append(observable_obj)
    if not response.added:
        raise HTTPException(
            status_code=400,
            detail="Failed to add any observables.",
        )
    return response


@router.get("/{id}")
@permission_on_target(roles.Permission.READ)
def details(httpreq: Request, id: str) -> ObservableTypes:
    """Returns details about an observable."""
    observable_obj = Observable.get(id)

    if not observable_obj:
        raise HTTPException(status_code=404, detail="Observable not found")
    observable_obj.get_tags()
    observable_obj.get_acls(httpreq.state.user)
    return observable_obj


@router.post("/{id}/context")
@permission_on_target(roles.Permission.WRITE)
def add_context(
    httpreq: Request, id: str, request: AddContextRequest
) -> ObservableTypes:
    """Adds context to an observable."""
    observable_obj = Observable.get(id)
    if not observable_obj:
        raise HTTPException(status_code=404, detail=f"Observable {id} not found")

    old_context = observable_obj.context.copy()
    refreshed_obj = observable_obj.add_context(
        request.source, request.context, skip_compare=request.skip_compare
    )
    observable_obj.context = old_context
    audit.log_timeline(httpreq.state.username, refreshed_obj, old=observable_obj)
    return refreshed_obj


@router.post("/{id}/context/delete")
@permission_on_target(roles.Permission.WRITE)
def delete_context(
    httpreq: Request, id, request: DeleteContextRequest
) -> ObservableTypes:
    """Removes context to an observable."""
    observable_obj = Observable.get(id)
    if not observable_obj:
        raise HTTPException(status_code=404, detail=f"Observable {id} not found")

    old_context = observable_obj.context.copy()
    refreshed_obj = observable_obj.delete_context(
        request.source, request.context, skip_compare=request.skip_compare
    )
    observable_obj.context = old_context
    audit.log_timeline(httpreq.state.username, refreshed_obj, old=observable_obj)
    return refreshed_obj


@router.post("/search")
def search(
    httpreq: Request, request: ObservableSearchRequest
) -> ObservableSearchResponse:
    """Searches for observables."""
    query = request.query
    tags = query.pop("tags", [])
    if request.type:
        query["type"] = request.type
    observables, total = Observable.filter(
        query,
        tag_filter=tags,
        offset=request.page * request.count,
        count=request.count,
        sorting=request.sorting,
        graph_queries=[("tags", "tagged", "outbound", "name")],
        user=httpreq.state.user,
    )
    return ObservableSearchResponse(observables=observables, total=total)


@router.post("/add_text", deprecated=True)
@global_permission(roles.Permission.WRITE)
def add_text(httpreq: Request, request: AddTextRequest) -> ObservableTypes:
    """Adds and returns an observable for a given string, attempting to guess
    its type."""
    try:
        new = observable.save(value=request.text, tags=request.tags)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    audit.log_timeline(httpreq.state.username, new)
    httpreq.state.user.link_to_acl(new, roles.Role.OWNER)
    return new


@router.post("/import/text")
@global_permission(roles.Permission.WRITE)
def import_from_text(
    httpreq: Request, request: ImportTextRequest
) -> BulkObservableAddResponse:
    """Adds and returns an observable for a given string, attempting to guess
    its type."""
    try:
        observables, unknown = observable.save_from_text(
            text=request.text, tags=request.tags
        )

    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

    for obs in observables:
        audit.log_timeline(httpreq.state.username, obs, action="import-text")
        httpreq.state.user.link_to_acl(obs, roles.Role.OWNER)
    return BulkObservableAddResponse(added=observables, failed=unknown)


@router.post("/import/url")
@global_permission(roles.Permission.WRITE)
def import_from_url(
    httpreq: Request, request: ImportUrlRequest
) -> BulkObservableAddResponse:
    """Adds and returns observables from a given url, attempting to guess
    their types."""
    if not validators.url(request.text):
        raise HTTPException(status_code=400, detail="Invalid URL")
    try:
        observables, unknown = observable.save_from_url(
            value=request.url, tags=request.tags
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

    for obs in observables:
        audit.log_timeline(httpreq.state.username, obs, action="import-url")
        httpreq.state.user.link_to_acl(obs, roles.Role.OWNER)
    return BulkObservableAddResponse(added=observables, failed=unknown)


@router.post("/import/file")
@global_permission(roles.Permission.WRITE)
def import_from_file(
    httpreq: Request,
    file: Annotated[UploadFile, File()],
    tags: Annotated[list[str], Form()],
) -> BulkObservableAddResponse:
    """Adds and returns observables from a given url, attempting to guess
    their types."""
    if file.size > MAX_FILE_UPLOAD:
        raise HTTPException(status_code=400, detail="File too large")
    try:
        # we can't use request.file object because it's not async
        observables, unknown = observable.save_from_file(file=file.file, tags=tags)

    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

    for obs in observables:
        audit.log_timeline(httpreq.state.username, obs, action="import-file")
        httpreq.state.user.link_to_acl(obs, roles.Role.OWNER)
    return BulkObservableAddResponse(added=observables, failed=unknown)


@router.post("/tag")
@permission_on_ids(roles.Permission.WRITE)
def tag_observable(
    httpreq: Request, request: ObservableTagRequest
) -> ObservableTagResponse:
    """Tags a set of observables, individually or in bulk."""
    observables = []
    for observable_id in request.ids:
        observable_obj = Observable.get(observable_id)
        if not observable_obj:
            raise HTTPException(
                status_code=400,
                detail="Tagging request contained an unknown observable: ID:{observable_id}",
            )
        observables.append(observable_obj)

    observable_tags = {}
    for observable_obj in observables:
        old_tags = [tag[1].name for tag in observable_obj.get_tags()]
        observable_obj = observable_obj.tag(request.tags, strict=request.strict)
        audit.log_timeline_tags(httpreq.state.username, observable_obj, old_tags)
        observable_tags[observable_obj.extended_id] = observable_obj.tags

    return ObservableTagResponse(tagged=len(observables), tags=observable_tags)


@router.delete("/{id}")
@permission_on_target(roles.Permission.DELETE)
def delete(httpreq: Request, id: str) -> None:
    """Deletes an observable."""
    observable_obj = Observable.get(id)
    if not observable_obj:
        raise HTTPException(status_code=404, detail="Observable not found")
    audit.log_timeline(httpreq.state.username, observable_obj, action="delete")
    observable_obj.delete()
