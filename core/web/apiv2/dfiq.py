import os
import tempfile
from io import BytesIO
from zipfile import ZipFile

from fastapi import APIRouter, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, ValidationError

from core.schemas import audit, dfiq, rbac, roles
from core.schemas.rbac import global_permission, permission_on_target


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
    error: str | list[dict] = ""
    error_type: str = "message"


class PatchDFIQRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dfiq_yaml: str | None = None
    dfiq_object: dfiq.DFIQTypes | None = None
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


class DFIQConfigResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage_types: list[str]
    step_types: list[str]


# API endpoints
router = APIRouter()


@router.get("/config")
def config() -> DFIQConfigResponse:
    all_questions = dfiq.DFIQQuestion.list()

    stage_types = set()
    step_types = set()

    for question in all_questions:
        for approach in question.approaches:
            for step in approach.steps:
                stage_types.add(step.stage)
                step_types.add(step.type)

    if None in stage_types:
        stage_types.remove(None)
    if None in step_types:
        step_types.remove(None)

    return DFIQConfigResponse(
        stage_types=sorted(list(stage_types)),
        step_types=sorted(list(step_types)),
    )


@router.post("/from_archive")
@global_permission(roles.Permission.WRITE)
def from_archive(httpreq: Request, archive: UploadFile) -> dict[str, int]:
    """Uncompresses a ZIP archive and processes the DFIQ content inside it."""
    with tempfile.TemporaryDirectory() as tempdir:
        contents = archive.file.read()
        ZipFile(BytesIO(contents)).extractall(path=tempdir)
        dfiq_addition = dfiq.read_from_data_directory(
            f"{tempdir}/*/*.yaml", user=httpreq.state.user.username
        )
        for indicator in dfiq_addition.indicators:
            rbac.set_acls(indicator, httpreq.state.user)
        for dfiq_object in dfiq_addition.dfiq:
            rbac.set_acls(dfiq_object, httpreq.state.user)

    return {"total_added": len(dfiq_addition.dfiq) + len(dfiq_addition.indicators)}


@router.post("/from_yaml")
@global_permission(roles.Permission.WRITE)
def new_from_yaml(httpreq: Request, request: NewDFIQRequest) -> dfiq.DFIQTypes:
    """Creates a new DFIQ object in the database."""
    try:
        new = dfiq.TYPE_MAPPING[request.dfiq_type].from_yaml(request.dfiq_yaml)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    # Ensure there is not an object with the same ID or UUID

    if new.dfiq_id and dfiq.DFIQBase.find(dfiq_id=new.dfiq_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"DFIQ with id {new.dfiq_id} already exists",
        )

    if dfiq.DFIQBase.find(uuid=new.uuid):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"DFIQ with uuid {new.uuid} already exists",
        )

    intended_parents = []

    # Scenarios don't have parent IDs
    parent_ids = [] if new.type == dfiq.DFIQType.scenario else new.parent_ids
    for parent_id in parent_ids:
        parent = dfiq.DFIQBase.find(dfiq_id=parent_id)
        if not parent:
            parent = dfiq.DFIQBase.find(uuid=parent_id)
        intended_parents.append(parent)
    if not all(intended_parents):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing parent(s), provided {new.parent_ids}",
        )

    new = new.save()
    httpreq.state.user.link_to_acl(new, roles.Role.OWNER)
    audit.log_timeline(httpreq.state.username, new)

    try:
        new.update_parents()
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    if request.update_indicators and new.type == dfiq.DFIQType.question:
        dfiq.extract_indicators(new, user=httpreq.state.user.username)

    return new


@router.post("/to_archive")
def to_archive(httpreq: Request, request: DFIQSearchRequest) -> FileResponse:
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
        user=httpreq.state.user,
    )

    _TYPE_TO_DUMP_DIR = {
        dfiq.DFIQType.scenario: "scenarios",
        dfiq.DFIQType.facet: "facets",
        dfiq.DFIQType.question: "questions",
    }

    with tempfile.TemporaryDirectory() as tempdir:
        public_objs = []
        internal_objs = []
        for obj in dfiq_objects:
            if obj.dfiq_tags and "internal" in obj.dfiq_tags:
                internal_objs.append(obj)
            else:
                if obj.type == dfiq.DFIQType.question:
                    public_version = obj.model_copy()
                    internal_approaches = False
                    for approach in obj.approaches:
                        if "internal" in approach.tags:
                            internal_approaches = True
                            break
                    if internal_approaches:
                        public_version.approaches = [
                            a for a in obj.approaches if "internal" not in a.tags
                        ]
                        public_objs.append(public_version)
                        internal_objs.append(obj)
                    else:
                        public_objs.append(obj)
                else:
                    public_objs.append(obj)

        for dir_name in ["public", "internal"]:
            os.makedirs(f"{tempdir}/{dir_name}")

        for obj in public_objs:
            with open(f"{tempdir}/public/{obj.uuid}.yaml", "w") as f:
                f.write(obj.to_yaml())

        for obj in internal_objs:
            with open(f"{tempdir}/internal/{obj.uuid}.yaml", "w") as f:
                f.write(obj.to_yaml())

        with tempfile.NamedTemporaryFile(delete=False) as archive:
            with ZipFile(archive, "w") as zipf:
                for obj in public_objs:
                    zipf.write(
                        f"{tempdir}/public/{obj.uuid}.yaml",
                        f"public/{_TYPE_TO_DUMP_DIR[obj.type]}/{obj.uuid}.yaml",
                    )
                for obj in internal_objs:
                    zipf.write(
                        f"{tempdir}/internal/{obj.uuid}.yaml",
                        f"internal/{_TYPE_TO_DUMP_DIR[obj.type]}/{obj.uuid}.yaml",
                    )

    return FileResponse(archive.name, media_type="application/zip", filename="dfiq.zip")


@router.post("/validate")
def validate_dfiq_yaml(request: DFIQValidateRequest) -> DFIQValidateResponse:
    """Validates a DFIQ YAML string."""
    try:
        obj = dfiq.TYPE_MAPPING[request.dfiq_type].from_yaml(request.dfiq_yaml)
    except ValidationError as error:
        error_objs: list[dict] = []
        for pydantic_error in error.errors():
            error_objs.append(
                {
                    "model": error.title,
                    "field": ".".join(
                        [str(locerr) for locerr in pydantic_error["loc"]]
                    ),
                    "error": pydantic_error["msg"],
                    "input": pydantic_error["input"],
                }
            )
        return DFIQValidateResponse(
            valid=False, error=error_objs, error_type="pydantic"
        )
    except ValueError as error:
        return DFIQValidateResponse(valid=False, error=str(error))
    except KeyError as error:
        return DFIQValidateResponse(valid=False, error=f"Invalid DFIQ type: {error}")

    if request.check_id and obj.dfiq_id and dfiq.DFIQBase.find(dfiq_id=obj.dfiq_id):
        return DFIQValidateResponse(
            valid=False, error=f"DFIQ with id {obj.dfiq_id} already exists"
        )

    return DFIQValidateResponse(valid=True, error="")


@router.patch("/{id}")
@permission_on_target(roles.Permission.WRITE)
def patch(httpreq: Request, request: PatchDFIQRequest, id: str) -> dfiq.DFIQTypes:
    """Modifies an DFIQ object in the database."""

    if request.dfiq_object and request.dfiq_yaml:
        raise HTTPException(
            status_code=400,
            detail="Cannot provide both dfiq_object and dfiq_yaml in the request",
        )

    if not request.dfiq_object and not request.dfiq_yaml:
        raise HTTPException(
            status_code=400,
            detail="Either dfiq_object or dfiq_yaml must be provided in the request",
        )

    db_dfiq: dfiq.DFIQTypes = dfiq.DFIQBase.get(id)  # type: ignore
    if not db_dfiq:
        raise HTTPException(status_code=404, detail=f"DFIQ object {id} not found")

    if request.dfiq_yaml:
        try:
            update_data = dfiq.TYPE_MAPPING[db_dfiq.type].from_yaml(request.dfiq_yaml)
        except ValueError as error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(error)
            )

    if request.dfiq_object:
        update_data = request.dfiq_object

    if db_dfiq.type != update_data.type:
        raise HTTPException(
            status_code=400,
            detail=f"DFIQ type mismatch: {db_dfiq.type} != {update_data.type}",
        )
    db_dfiq.get_acls()
    updated_dfiq = db_dfiq.model_copy(
        update=update_data.model_dump(exclude=["created"])
    )
    new = updated_dfiq.save()
    new.get_acls()
    audit.log_timeline(httpreq.state.username, new, old=db_dfiq)
    new.update_parents()

    if request.update_indicators and new.type == dfiq.DFIQType.question:
        dfiq.extract_indicators(new, user=httpreq.state.user.username)

    return new


@router.get("/")
def get(
    httpreq: Request,
    name: str,
    type: dfiq.DFIQType | None = None,
) -> dfiq.DFIQTypes:
    """Gets an dfiq_obj by name."""

    params = {"name": name}
    if type:
        params["type"] = type

    dfiq_obj = dfiq.DFIQBase.find(**params)
    if not dfiq_obj:
        raise HTTPException(
            status_code=404,
            detail=f"DFIQ {name} not found (type: {type or 'any'})",
        )

    if not rbac.RBAC_ENABLED or httpreq.state.user.admin:
        return dfiq_obj

    if not httpreq.state.user.has_permissions(
        dfiq_obj.extended_id, roles.Permission.READ
    ):
        raise HTTPException(
            status_code=403,
            detail=f"Forbidden: missing privileges {roles.Permission.READ} on target {dfiq_obj.extended_id}",
        )
    return dfiq_obj


@router.get("/{id}")
@permission_on_target(roles.Permission.READ)
def details(httpreq: Request, id: str) -> dfiq.DFIQTypes:
    """Returns details about a DFIQ object."""
    db_dfiq: dfiq.DFIQTypes = dfiq.DFIQBase.get(id)  # type: ignore
    if not db_dfiq:
        raise HTTPException(status_code=404, detail=f"DFIQ object {id} not found")
    db_dfiq.get_acls()
    return db_dfiq


@router.delete("/{id}")
@permission_on_target(roles.Permission.DELETE)
def delete(httpreq: Request, id: str) -> None:
    """Deletes a DFIQ object."""
    db_dfiq = dfiq.DFIQBase.get(id)
    if not db_dfiq:
        raise HTTPException(status_code=404, detail=f"DFIQ object {id} not found")

    all_children, _ = dfiq.DFIQBase.filter(
        query_args={"parent_ids": db_dfiq.uuid}, wildcard=False
    )
    if db_dfiq.dfiq_id:
        children, _ = dfiq.DFIQBase.filter(
            query_args={"parent_ids": db_dfiq.dfiq_id}, wildcard=False
        )
        if children:
            all_children.extend(children)
    for child in all_children:
        if db_dfiq.dfiq_id in child.parent_ids:
            child.parent_ids.remove(db_dfiq.dfiq_id)
        if db_dfiq.uuid in child.parent_ids:
            child.parent_ids.remove(db_dfiq.uuid)
        audit.log_timeline(
            httpreq.state.username,
            child,
            action="delete-parent",
            details={"parent": db_dfiq.id},
        )
        child.save()

    audit.log_timeline(httpreq.state.username, db_dfiq, action="delete")
    db_dfiq.delete()


@router.post("/search")
def search(httpreq: Request, request: DFIQSearchRequest) -> DFIQSearchResponse:
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
        user=httpreq.state.user,
    )
    return DFIQSearchResponse(dfiq=dfiq_objects, total=total)
