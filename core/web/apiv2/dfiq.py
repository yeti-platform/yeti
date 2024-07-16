import tempfile
from io import BytesIO
from zipfile import ZipFile

from fastapi import APIRouter, HTTPException, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, ValidationError

from core.schemas import dfiq


# Request schemas
class NewDFIQRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dfiq_yaml: str
    dfiq_type: dfiq.DFIQType
    update_indicators: bool = False


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
    update_indicators: bool = False


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


@router.post("/from_archive")
async def from_archive(archive: UploadFile) -> dict[str, int]:
    """Uncompresses a ZIP archive and processes the DFIQ content inside it."""
    tempdir = tempfile.TemporaryDirectory()
    contents = await archive.read()
    ZipFile(BytesIO(contents)).extractall(path=tempdir.name)
    total_added = dfiq.read_from_data_directory(tempdir.name)
    return {"total_added": total_added}


@router.post("/from_yaml")
async def new_from_yaml(request: NewDFIQRequest) -> dfiq.DFIQTypes:
    """Creates a new DFIQ object in the database."""
    try:
        new = dfiq.TYPE_MAPPING[request.dfiq_type].from_yaml(request.dfiq_yaml)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    # Ensure there is not an object with the same ID:
    if dfiq.DFIQBase.find(dfiq_id=new.dfiq_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"DFIQ with id {new.dfiq_id} already exists",
        )

    new = new.save()

    try:
        new.update_parents()
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    if request.update_indicators and new.type == dfiq.DFIQType.approach:
        dfiq.extract_indicators(new)

    return new


@router.post("/to_archive")
async def to_archive(request: DFIQSearchRequest) -> FileResponse:
    """Compresses DFIQ objects into a ZIP archive.

    The structure of the archive is as follows:
    - {public, internal}/
      - type/
        - dfiq_id.yaml
    """
    dfiq_objects, _ = dfiq.DFIQBase.filter(
        query_args=request.query,
        offset=request.page * request.count,
        count=request.count,
        sorting=request.sorting,
        aliases=request.filter_aliases,
    )

    tempdir = tempfile.TemporaryDirectory()
    for obj in dfiq_objects:
        with open(f"{tempdir.name}/{obj.dfiq_id}.yaml", "w") as f:
            f.write(obj.to_yaml())

    with tempfile.NamedTemporaryFile(delete=False) as archive:
        with ZipFile(archive, "w") as zipf:
            for obj in dfiq_objects:
                subdir = "internal" if obj.internal else "public"
                zipf.write(
                    f"{tempdir.name}/{obj.dfiq_id}.yaml",
                    f"{subdir}/{obj.type}/{obj.dfiq_id}.yaml",
                )

    return FileResponse(archive.name, media_type="application/zip", filename="dfiq.zip")


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

    try:
        update_data = dfiq.TYPE_MAPPING[db_dfiq.type].from_yaml(request.dfiq_yaml)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    if db_dfiq.type != update_data.type:
        raise HTTPException(
            status_code=400,
            detail=f"DFIQ type mismatch: {db_dfiq.type} != {update_data.type}",
        )
    updated_dfiq = db_dfiq.model_copy(update=update_data.model_dump())
    new = updated_dfiq.save()
    new.update_parents()

    if request.update_indicators and new.type == dfiq.DFIQType.approach:
        dfiq.extract_indicators(new)

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
