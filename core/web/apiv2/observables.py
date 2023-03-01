from fastapi import APIRouter, HTTPException

from typing import Iterable
from core.schemas.observable import Observable, NewObservableRequest, ObservableUpdateRequest, AddTextRequest
import datetime

# API endpoints
observables_router = APIRouter()

@observables_router.get('/')
async def observables_root() -> Iterable[Observable]:
    return Observable.list()

@observables_router.post('/')
async def new_observable(request: NewObservableRequest) -> Observable:
    """Creates a new observable in the database."""
    observable = Observable(
        value=request.value,
        type=request.type,
        created=datetime.datetime.now(datetime.timezone.utc)
    )
    new_observable = observable.save()
    return new_observable

@observables_router.get('/{observable_id}')
async def observable_details(observable_id) -> Observable:
    """Returns details about an observable."""
    observable = Observable.get(observable_id)
    if not observable:
        raise HTTPException(status_code=404, detail="Observable not found")
    return observable

@observables_router.put('/{observable_id}')
async def observable_update(observable_id, request: ObservableUpdateRequest) -> Observable:
    """Updates an observable."""
    observable = Observable.get(observable_id)
    if not observable:
        raise HTTPException(status_code=404, detail="Item not found")

    if request.context:
        if request.replace:
            observable.context = {}
        observable.context.update(request.context)

    if request.tags:
        if request.replace:
            observable.tags = []
        observable.tags.extend(request.tags)

    observable = observable.save()
    return observable

@observables_router.post('/add_text')
async def add_text(request: AddTextRequest) -> Observable:
    """Adds and returns an observable for a given string, attempting to guess its type."""
    try:
        return Observable.add_text(request.text, request.tags)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
