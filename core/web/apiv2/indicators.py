import datetime
from typing import Iterable

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.schemas import indicator


# Request schemas
class NewIndicatorRequest(BaseModel):
    indicator: indicator.IndicatorTypes

class PatchIndicatorRequest(BaseModel):
    indicator: indicator.IndicatorTypes

class IndicatorSearchRequest(BaseModel):
    name: str | None = None
    type: indicator.IndicatorType | None = None
    count: int = 50
    page: int = 0

class IndicatorSearchResponse(BaseModel):
    indicators: list[indicator.IndicatorTypes]
    total: int

# API endpoints
router = APIRouter()

@router.get('/')
async def indicators_root() -> Iterable[indicator.IndicatorTypes]:
    return indicator.Indicator.list()

@router.post('/')
async def new(request: NewIndicatorRequest) -> indicator.IndicatorTypes:
    """Creates a new indicator in the database."""
    new = request.indicator.save()
    return new

@router.patch('/{indicator_id}')
async def patch(request: PatchIndicatorRequest, indicator_id) -> indicator.IndicatorTypes:
    """Modifies an indicator in the database."""
    db_indicator: indicator.IndicatorTypes = indicator.Indicator.get(indicator_id)  # type: ignore
    update_data = request.indicator.model_dump(exclude_unset=True)
    updated_indicator = db_indicator.model_copy(update=update_data)
    new = updated_indicator.save()
    return new

@router.get('/{indicator_id}')
async def details(indicator_id) -> indicator.IndicatorTypes:
    """Returns details about an indicator."""
    db_indicator: indicator.IndicatorTypes = indicator.Indicator.get(indicator_id)  # type: ignore
    if not db_indicator:
        raise HTTPException(status_code=404, detail="indicator not found")
    return db_indicator

@router.post('/search')
async def search(request: IndicatorSearchRequest) -> IndicatorSearchResponse:
    """Searches for indicators."""
    request_args = request.model_dump()
    count = request_args.pop('count')
    page = request_args.pop('page')
    indicators, total = indicator.Indicator.filter(request_args, offset=request.page*request.count, count=request.count)
    return IndicatorSearchResponse(indicators=indicators, total=total)
