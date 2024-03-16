from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, ValidationError

from core.schemas import dfiq


# Request schemas
class NewDFIQRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dfiq_yaml: str
    dfiq_type: dfiq.DFIQType


class DFIQValidateRequest(NewDFIQRequest):
    model_config = ConfigDict(extra="forbid")
    check_id: bool = False


class DFIQValidateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    valid: bool
    error: str


class PatchDFIQRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dfiq_yaml: str
    dfiq_type: dfiq.DFIQType


class DFIQSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: dict[str, str | int | list] = {}
    type: dfiq.DFIQType | None = None
    sorting: list[tuple[str, bool]] = []
    filter_aliases: list[tuple[str, str]] = []
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


@router.post("/validate")
async def validate_dfiq_yaml(request: DFIQValidateRequest) -> DFIQValidateResponse:
    """Validates a DFIQ YAML string."""
    try:
        obj = dfiq.TYPE_MAPPING[request.dfiq_type].from_yaml(request.dfiq_yaml)
    except ValidationError as error:
        return DFIQValidateResponse(valid=False, error=str(error.errors()))
    except ValueError as error:
        return DFIQValidateResponse(valid=False, error=str(error))
    except KeyError as error:
        return DFIQValidateResponse(valid=False, error=f"Invalid DFIQ type: {error}")

    if request.check_id and dfiq.DFIQBase.find(dfiq_id=obj.dfiq_id):
        return DFIQValidateResponse(
            valid=False, error=f"DFIQ with id {obj.dfiq_id} already exists"
        )

    return DFIQValidateResponse(valid=True, error="")


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
        query_args=query,
        offset=request.page * request.count,
        count=request.count,
        sorting=request.sorting,
        aliases=request.filter_aliases,
    )
    return DFIQSearchResponse(dfiq=dfiq_objects, total=total)
