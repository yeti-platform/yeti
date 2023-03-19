import datetime
from typing import Iterable

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.schemas.observable import Observable
from core.schemas.graph import GraphSearchRequest, GraphSearchResponse, GraphAddRequest, Relationship

# API endpoints
router = APIRouter()

MAPPINGS = {
    'observables': Observable
}

@router.post('/search')
async def search(request: GraphSearchRequest) -> GraphSearchResponse:
    """Fetches neighbros for a given Yeti Object."""
    object_type, object_id = request.source.split('/')
    if object_type not in MAPPINGS:
        raise HTTPException(status_code=400, detail='Invalid object type')
    yeti_object = MAPPINGS[object_type].get(object_id)
    if not yeti_object:
        raise HTTPException(
            status_code=404, detail=f'Source object {request.source} not found')
    neighbors = yeti_object.neighbors(
        link_type=request.link_type,
        direction=request.direction,
        include_original=request.include_original,
        hops=request.hops,
    )
    return neighbors

@router.post('/add')
async def add(request: GraphAddRequest) -> Relationship:
    """Adds a link to the graph."""
    source_type, source_id = request.source.split('/')
    target_type, target_id = request.target.split('/')

    if source_type not in MAPPINGS:
        raise HTTPException(
            status_code=400,
            detail=f'Invalid source object type: {source_type}')
    if target_type not in MAPPINGS:
        raise HTTPException(
            status_code=400,
            detail=f'Invalid target object type: {target_type}')

    source_object = MAPPINGS[source_type].get(source_id)
    target_object = MAPPINGS[target_type].get(target_id)
    if source_object is None:
        raise HTTPException(
            status_code=404,
            detail=f'Source object {request.source} not found')
    if target_object is None:
        raise HTTPException(
            status_code=404,
            detail=f'Target object {request.target} not found')

    relationship = source_object.link_to(
        target_object, request.link_type, request.description)
    return relationship

#TODO: Route to delete link
