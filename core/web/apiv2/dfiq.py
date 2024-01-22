from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from core.schemas import dfiq


# Request schemas
class NewDFIQRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    dfiq: dfiq.DFIQTypes


class PatchDFIQRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    dfiq: dfiq.DFIQTypes


class DFIQSearchRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')

    query: dict[str, str|int|list] = {}
    type: dfiq.DFIQType | None = None
    count: int = 50
    page: int = 0


class DFIQSearchResponse(BaseModel):
    model_config = ConfigDict(extra='forbid')

    dfiq: list[dfiq.DFIQTypes]
    total: int


# API endpoints
router = APIRouter()


@router.post("/")
async def new(request: NewDFIQRequest) -> dfiq.DFIQTypes:
    """Creates a new DFIQ object in the database."""
    new = request.dfiq.save()
    return new


@router.patch("/{dfiq_id}")
async def patch(
    request: PatchDFIQRequest, dfiq_id
) -> dfiq.DFIQTypes:
    """Modifies an DFIQ object in the database."""
    db_dfiq: dfiq.DFIQTypes = dfiq.DFIQBase.get(dfiq_id)  # type: ignore
    update_data = request.dfiq.model_dump(exclude_unset=True)
    updated_dfiq = db_dfiq.model_copy(update=update_data)
    new = updated_dfiq.save()
    return new


@router.get("/{dfiq_id}")
async def details(dfiq_id) -> dfiq.DFIQTypes:
    """Returns details about a DFIQ object."""
    db_dfiq: dfiq.DFIQTypes = dfiq.DFIQBase.get(dfiq_id)  # type: ignore
    if not db_dfiq:
        raise HTTPException(status_code=404, detail=f"DFIQ object {dfiq_id} not found")
    return db_dfiq


@router.delete("/{dfiq_id}")
async def delete(dfiq_id: str) -> None:
    """Deletes a DFIQ object."""
    db_dfiq = dfiq.DFIQBase.get(dfiq_id)
    if not db_dfiq:
        raise HTTPException(status_code=404, detail="DFIQ object {dfiq_id} not found")
    db_dfiq.delete()


@router.post("/search")
async def search(request: DFIQSearchRequest) -> DFIQSearchResponse:
    """Searches for DFIQ objects."""
    query = request.query
    if request.type:
        query["type"] = request.type
    dfiq_objects, total = dfiq.DFIQBase.filter(
        query, offset=request.page * request.count, count=request.count
    )
    return DFIQSearchResponse(dfiq=dfiq_objects, total=total)
