from typing import Annotated, Iterable, List

import validators
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, ConfigDict, Field, conlist, field_validator

from core.config.config import yeti_config
from core.schemas import graph, observable
from core.schemas.observable import Observable, ObservableType, ObservableTypes
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


@router.get("/")
def observables_root() -> Iterable[Observable]:
    return Observable.list()


@router.post("/")
def new(request: NewObservableRequest) -> ObservableTypes:
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
        return observable.save(
            type=request.type, value=request.value, tags=request.tags
        )
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Failed to add observable",
        )


@router.post("/extended")
def new_extended(request: NewExtendedObservableRequest) -> ObservableTypes:
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
        return observable.save(
            **request.observable.model_dump(exclude={"tags"}), tags=request.tags
        )
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Failed to add observable",
        )


@router.patch("/{observable_id}")
def patch(request: PatchObservableRequest, observable_id) -> ObservableTypes:
    """Modifies observable in the database."""
    db_observable = Observable.get(observable_id)
    if not db_observable:
        raise HTTPException(
            status_code=404, detail=f"Observable {observable_id} not found"
        )
    if db_observable.type != request.observable.type:
        raise HTTPException(
            status_code=400,
            detail=f"Observable {observable_id} type mismatch. Provided '{request.observable.type}'. Expected '{db_observable.type}'",
        )
    update_data = request.observable.model_dump(exclude_unset=True)
    updated_observable = db_observable.model_copy(update=update_data)
    new = updated_observable.save()
    return new


@router.post("/bulk")
def bulk_add(request: NewBulkObservableAddRequest) -> BulkObservableAddResponse:
    """Bulk-creates new observables in the database."""
    response = BulkObservableAddResponse()
    for new_observable in request.observables:
        try:
            observable_obj = observable.save(
                type=new_observable.type,
                value=new_observable.value,
                tags=new_observable.tags,
            )
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


@router.get("/{observable_id}")
def details(observable_id) -> ObservableTypes:
    """Returns details about an observable."""
    observable_obj = Observable.get(observable_id)
    if not observable_obj:
        raise HTTPException(status_code=404, detail="Observable not found")
    observable_obj.get_tags()
    return observable_obj


@router.post("/{observable_id}/context")
def add_context(observable_id, request: AddContextRequest) -> ObservableTypes:
    """Adds context to an observable."""
    observable_obj = Observable.get(observable_id)
    if not observable_obj:
        raise HTTPException(
            status_code=404, detail=f"Observable {observable_id} not found"
        )

    observable_obj = observable_obj.add_context(
        request.source, request.context, skip_compare=request.skip_compare
    )
    return observable_obj


@router.post("/{observable_id}/context/delete")
def delete_context(observable_id, request: DeleteContextRequest) -> ObservableTypes:
    """Removes context to an observable."""
    observable_obj = Observable.get(observable_id)
    if not observable_obj:
        raise HTTPException(
            status_code=404, detail=f"Observable {observable_id} not found"
        )

    observable_obj = observable_obj.delete_context(
        request.source, request.context, skip_compare=request.skip_compare
    )
    return observable_obj


@router.post("/search")
def search(request: ObservableSearchRequest) -> ObservableSearchResponse:
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
    )
    return ObservableSearchResponse(observables=observables, total=total)


@router.post("/add_text", deprecated=True)
def add_text(request: AddTextRequest) -> ObservableTypes:
    """Adds and returns an observable for a given string, attempting to guess
    its type."""
    try:
        return observable.save(value=request.text, tags=request.tags)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@router.post("/import/text")
def import_from_text(request: ImportTextRequest) -> BulkObservableAddResponse:
    """Adds and returns an observable for a given string, attempting to guess
    its type."""
    try:
        observables, unknown = observable.save_from_text(
            text=request.text, tags=request.tags
        )
        response = BulkObservableAddResponse(added=observables, failed=unknown)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    return response


@router.post("/import/url")
def import_from_url(request: ImportUrlRequest) -> BulkObservableAddResponse:
    """Adds and returns observables from a given url, attempting to guess
    their types."""
    if not validators.url(request.text):
        raise HTTPException(status_code=400, detail="Invalid URL")
    try:
        observables, unknown = observable.save_from_url(
            value=request.url, tags=request.tags
        )
        response = BulkObservableAddResponse(added=observables, failed=unknown)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    return response


@router.post("/import/file")
def import_from_file(
    file: Annotated[UploadFile, File()], tags: Annotated[list[str], Form()]
) -> BulkObservableAddResponse:
    """Adds and returns observables from a given url, attempting to guess
    their types."""
    if file.size > MAX_FILE_UPLOAD:
        raise HTTPException(status_code=400, detail="File too large")
    try:
        # we can't use request.file object because it's not async
        observables, unknown = observable.save_from_file(file=file.file, tags=tags)
        response = BulkObservableAddResponse(added=observables, failed=unknown)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    return response


@router.post("/tag")
def tag_observable(request: ObservableTagRequest) -> ObservableTagResponse:
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
        observable_obj.tag(request.tags, strict=request.strict)
        observable_tags[observable_obj.extended_id] = observable_obj.tags

    return ObservableTagResponse(tagged=len(observables), tags=observable_tags)


@router.delete("/{observable_id}")
def delete(observable_id: str) -> None:
    """Deletes an observable."""
    observable_obj = Observable.get(observable_id)
    if not observable_obj:
        raise HTTPException(status_code=404, detail="Observable not found")
    observable_obj.delete()
