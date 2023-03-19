import datetime
from typing import Iterable

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.schemas.observable import Observable
from core.schemas.graph import GraphSearchRequest, GraphSearchResponse

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
