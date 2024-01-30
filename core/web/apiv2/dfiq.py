from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict

from core.schemas import dfiq


# Request schemas
class NewDFIQRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dfiq_yaml: str
    dfiq_type: dfiq.DFIQType


class PatchDFIQRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dfiq_yaml: str
    dfiq_type: dfiq.DFIQType


class DFIQSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: dict[str, str | int | list] = {}
    type: dfiq.DFIQType | None = None
    count: int = 50
    page: int = 0


class DFIQSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dfiq: list[dfiq.DFIQTypes]
    total: int


# API endpoints
router = APIRouter()


@router.post("/from_yaml")
async def new_from_yaml(request: NewDFIQRequest) -> dfiq.DFIQTypes:
    """Creates a new DFIQ object in the database."""
    try:
        new = dfiq.TYPE_MAPPING[request.dfiq_type].from_yaml(request.dfiq_yaml)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    new = new.save()

    try:
        new.update_parents()
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    return new


@router.patch("/{dfiq_id}")
async def patch(request: PatchDFIQRequest, dfiq_id) -> dfiq.DFIQTypes:
    """Modifies an DFIQ object in the database."""
    db_dfiq: dfiq.DFIQTypes = dfiq.DFIQBase.get(dfiq_id)  # type: ignore
    if not db_dfiq:
        raise HTTPException(status_code=404, detail=f"DFIQ object {dfiq_id} not found")

    update_data = dfiq.TYPE_MAPPING[db_dfiq.type].from_yaml(request.dfiq_yaml)

    if db_dfiq.type != update_data.type:
        raise HTTPException(
            status_code=400,
            detail=f"DFIQ type mismatch: {db_dfiq.type} != {update_data.type}",
        )
    updated_dfiq = db_dfiq.model_copy(update=update_data.model_dump())
    new = updated_dfiq.save()
    new.update_parents()
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
