from fastapi import APIRouter, HTTPException

from typing import Iterable
from core.schemas.observable import Observable, NewObservableRequest, ObservableUpdateRequest, AddTextRequest, ObservableSearchRequest, ObservableTagRequest
from core.schemas.tag import Tag, DEFAULT_EXPIRATION_DAYS
import datetime

# API endpoints
observables_router = APIRouter()

@observables_router.get('/')
async def observables_root() -> Iterable[Observable]:
    return Observable.list()

@observables_router.post('/')
async def new(request: NewObservableRequest) -> Observable:
    """Creates a new observable in the database."""
    observable = Observable(
        value=request.value,
        type=request.type,
        created=datetime.datetime.now(datetime.timezone.utc)
    )
    new = observable.save()
    return new

@observables_router.get('/{observable_id}')
async def details(observable_id) -> Observable:
    """Returns details about an observable."""
    observable = Observable.get(observable_id)
    if not observable:
        raise HTTPException(status_code=404, detail="Observable not found")
    return observable

@observables_router.put('/{observable_id}')
async def update(observable_id, request: ObservableUpdateRequest) -> Observable:
    """Updates an observable."""
    observable = Observable.get(observable_id)
    if not observable:
        raise HTTPException(status_code=404, detail="Item not found")

    if request.context:
        if request.replace:
            observable.context = {}
        observable.context.update(request.context)

    if request.tags:
        observable.tag(request.tags, strict=request.replace)

    observable = observable.save()
    return observable

@observables_router.post('/search')
async def search(request: ObservableSearchRequest) -> list[Observable]:
    """Searches for observables."""
    request_args = request.dict(exclude_unset=True)
    count = request_args.pop('count')
    page = request_args.pop('page')
    observables = Observable.filter(request_args, offset=page*count, count=count)
    return observables

@observables_router.post('/add_text')
async def add_text(request: AddTextRequest) -> Observable:
    """Adds and returns an observable for a given string, attempting to guess its type."""
    try:
        return Observable.add_text(request.text, request.tags)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

@observables_router.post('/tag')
async def tag_observable(request: ObservableTagRequest) -> dict:
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
        db_tag = Tag.get_by_key_value(name=tag)
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

#TODO: Add context /context (POST, DELETE)
#TODO: Bulk add observables /bulk (POST)
#TODO: Bulk tag observables /bulk-tag (POST)
