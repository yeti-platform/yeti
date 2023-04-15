import datetime
from typing import Iterable

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.schemas.observable import Observable, ObservableType
from core.schemas.tag import DEFAULT_EXPIRATION_DAYS, Tag


# Request schemas
class NewObservableRequest(BaseModel):
    value: str
    tags: list[str] = []
    type: ObservableType

class NewBulkObservableAddRequest(BaseModel):
    observables: list[NewObservableRequest]

class AddTextRequest(BaseModel):
    text: str
    tags: list[str] = []

class AddContextRequest(BaseModel):
    source: str
    context: dict
    skip_compare: set = set()

class DeleteContextRequest(AddContextRequest):
    pass

class ObservableSearchRequest(BaseModel):
    value: str | None = None
    # name: str | None = None
    type: ObservableType | None = None
    tags: list[str] = []
    count: int = 50
    page: int = 0

class ObservableTagRequest(BaseModel):
    ids: list[str]
    tags: list[str]
    strict: bool = False


# API endpoints
router = APIRouter()

@router.get('/')
async def observables_root() -> Iterable[Observable]:
    return Observable.list()

@router.post('/')
async def new(request: NewObservableRequest) -> Observable:
    """Creates a new observable in the database."""
    observable = Observable(
        value=request.value,
        type=request.type,
        created=datetime.datetime.now(datetime.timezone.utc)
    )
    new = observable.save()
    if request.tags:
        new = new.tag(request.tags)
    return new

@router.post('/bulk')
async def bulk_add(request: NewBulkObservableAddRequest) -> list[Observable]:
    """Bulk-creates new observables in the database."""
    added = []
    for new_observable in request.observables:
        if new_observable.type == ObservableType.guess:
            observable = Observable.add_text(
                new_observable.value, tags=new_observable.tags)
        else:
            observable = Observable(
                value=new_observable.value,
                type=new_observable.type,
                created=datetime.datetime.now(datetime.timezone.utc)
            ).save()
            if new_observable.tags:
                observable = observable.tag(new_observable.tags)
        added.append(observable)
    return added

@router.get('/{observable_id}')
async def details(observable_id) -> Observable:
    """Returns details about an observable."""
    observable = Observable.get(observable_id)
    if not observable:
        raise HTTPException(status_code=404, detail="Observable not found")
    return observable

@router.post('/{observable_id}/context')
async def add_context(observable_id, request: AddContextRequest) -> Observable:
    """Adds context to an observable."""
    observable = Observable.get(observable_id)
    if not observable:
        raise HTTPException(
            status_code=404, detail=f"Observable {observable_id} not found")

    observable = observable.add_context(
        request.source, request.context, skip_compare=request.skip_compare)
    return observable

@router.post('/{observable_id}/context/delete')
async def delete_context(observable_id, request: DeleteContextRequest) -> Observable:
    """Removes context to an observable."""
    observable = Observable.get(observable_id)
    if not observable:
        raise HTTPException(
            status_code=404, detail=f"Observable {observable_id} not found")

    observable = observable.delete_context(
        request.source, request.context, skip_compare=request.skip_compare)
    return observable

@router.post('/search')
async def search(request: ObservableSearchRequest) -> list[Observable]:
    """Searches for observables."""
    request_args = request.dict(exclude_unset=True)
    count = request_args.pop('count')
    page = request_args.pop('page')
    observables = Observable.filter(request_args, offset=page*count, count=count)
    return observables

@router.post('/add_text')
async def add_text(request: AddTextRequest) -> Observable:
    """Adds and returns an observable for a given string, attempting to guess
    its type."""
    try:
        return Observable.add_text(request.text, request.tags)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

@router.post('/tag')
async def tag_observable(request: ObservableTagRequest) -> dict:
    """Tags a set of observables, individually or in bulk."""
    observables = []
    for observable_id in request.ids:
        observable = Observable.get(observable_id)
        if not observable:
            raise HTTPException(status_code=400, detail="Tagging request contained an unknown observable: ID:{observable_id}")
        observables.append(observable)

    for observable in observables:
        observable.tag(request.tags, strict=request.strict)

    db_tags = []
    for tag in request.tags:
        db_tag = Tag.find(name=tag)
        if db_tag:
            db_tag.count += 1
        else:
            db_tag = Tag(
            name=tag,
            created=datetime.datetime.now(datetime.timezone.utc),
            default_expiration=datetime.timedelta(days=DEFAULT_EXPIRATION_DAYS))
        db_tag = db_tag.save()
        db_tags.append(db_tag)
    return {
        'tagged': len(observables),
        'tags': db_tags
    }
