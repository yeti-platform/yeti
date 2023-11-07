import datetime
from typing import Iterable

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from core.schemas import graph
from core.schemas.observable import Observable, ObservableType


# Request schemas
class NewObservableRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    value: str
    tags: list[str] = []
    type: ObservableType


class NewBulkObservableAddRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    observables: list[NewObservableRequest]


class AddTextRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    text: str
    tags: list[str] = []


class AddContextRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    source: str
    context: dict
    skip_compare: set = set()


class DeleteContextRequest(AddContextRequest):
    pass


class ObservableSearchRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    query: dict[str, str|int|list] = {}
    type: ObservableType | None = None
    count: int = 50
    page: int = 0


class ObservableSearchResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    observables: list[Observable]
    total: int


class ObservableTagRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    ids: list[str]
    tags: list[str]
    strict: bool = False

class ObservableTagResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    tagged: int
    tags: dict[str, dict[str, graph.TagRelationship]]


# API endpoints
router = APIRouter()


@router.get("/")
async def observables_root() -> Iterable[Observable]:
    return Observable.list()


@router.post("/")
async def new(request: NewObservableRequest) -> Observable:
    """Creates a new observable in the database.

    Raises:
        HTTPException(400) if observable already exists.
    """
    observable = Observable.find(value=request.value)
    if observable:
        raise HTTPException(
            status_code=400,
            detail=f"Observable with value {request.value} already exists",
        )
    observable = Observable(
        value=request.value,
        type=request.type,
        created=datetime.datetime.now(datetime.timezone.utc),
    )
    new = observable.save()
    if request.tags:
        new.tag(request.tags)
    return new


@router.post("/bulk")
async def bulk_add(request: NewBulkObservableAddRequest) -> list[Observable]:
    """Bulk-creates new observables in the database."""
    added = []
    for new_observable in request.observables:
        if new_observable.type == ObservableType.guess:
            observable = Observable.add_text(
                new_observable.value, tags=new_observable.tags
            )
        else:
            observable = Observable(
                value=new_observable.value,
                type=new_observable.type,
                created=datetime.datetime.now(datetime.timezone.utc),
            ).save()
            if new_observable.tags:
                observable = observable.tag(new_observable.tags)
        added.append(observable)
    return added


@router.get("/{observable_id}")
async def details(observable_id) -> Observable:
    """Returns details about an observable."""
    observable = Observable.get(observable_id)
    if not observable:
        raise HTTPException(status_code=404, detail="Observable not found")
    observable.get_tags()
    return observable


@router.post("/{observable_id}/context")
async def add_context(observable_id, request: AddContextRequest) -> Observable:
    """Adds context to an observable."""
    observable = Observable.get(observable_id)
    if not observable:
        raise HTTPException(
            status_code=404, detail=f"Observable {observable_id} not found"
        )

    observable = observable.add_context(
        request.source, request.context, skip_compare=request.skip_compare
    )
    return observable


@router.post("/{observable_id}/context/delete")
async def delete_context(observable_id, request: DeleteContextRequest) -> Observable:
    """Removes context to an observable."""
    observable = Observable.get(observable_id)
    if not observable:
        raise HTTPException(
            status_code=404, detail=f"Observable {observable_id} not found"
        )

    observable = observable.delete_context(
        request.source, request.context, skip_compare=request.skip_compare
    )
    return observable


@router.post("/search")
async def search(request: ObservableSearchRequest) -> ObservableSearchResponse:
    """Searches for observables."""
    query = request.query
    tags = query.pop('tags', [])
    if request.type:
        query["type"] = request.type
    observables, total = Observable.filter(
        query,
        tag_filter=tags,
        offset=request.page * request.count,
        count=request.count,
        sorting=[("created", False)],
        graph_queries=[('tags', 'tagged', 'outbound', 'name')]
    )
    return ObservableSearchResponse(observables=observables, total=total)


@router.post("/add_text")
async def add_text(request: AddTextRequest) -> Observable:
    """Adds and returns an observable for a given string, attempting to guess
    its type."""
    try:
        return Observable.add_text(request.text, request.tags)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@router.post("/tag")
async def tag_observable(request: ObservableTagRequest) -> ObservableTagResponse:
    """Tags a set of observables, individually or in bulk."""
    observables = []
    for observable_id in request.ids:
        observable = Observable.get(observable_id)
        if not observable:
            raise HTTPException(
                status_code=400,
                detail="Tagging request contained an unknown observable: ID:{observable_id}",
            )
        observables.append(observable)

    observable_tags = {}
    for observable in observables:
        observable.tag(request.tags, strict=request.strict)
        observable_tags[observable.extended_id] = observable.tags

    return ObservableTagResponse(tagged=len(observables), tags=observable_tags)
