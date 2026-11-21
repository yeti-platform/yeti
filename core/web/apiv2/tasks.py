import io
from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from core import taskscheduler
from core.schemas import rbac, roles
from core.schemas import user as user_schema
from core.schemas.task import ExportTask, Task, TaskParams, TaskType, TaskTypes
from core.schemas.template import Template
from core.web.apiv2.auth import GetCurrentUserWithPermissions


# Request schemas
class TaskSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    query: dict[str, str | int | list] = {}
    type: TaskType | None = None
    sorting: list[tuple[str, bool]] = []
    count: int = 100
    page: int = 0


class TaskSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tasks: list[Annotated[TaskTypes, Field(discriminator="type")]]
    total: int


class NewExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    export: ExportTask


class PatchExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    export: ExportTask


# API endpoints
router = APIRouter()


def _require_export_owner(user: user_schema.User, export: ExportTask) -> None:
    if not rbac.RBAC_ENABLED or user.admin:
        return
    if export.owner != user.username:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: only the export owner or an admin can access this export",
        )


@router.post("/{task_name}/run")
@rbac.global_permission(roles.Permission.WRITE)
def run(
    httpreq: Request, task_name: str, params: TaskParams | None = None
) -> dict[str, str]:
    """Runs a task asynchronously."""
    db_task = Task.find(name=task_name)
    if isinstance(db_task, ExportTask):
        _require_export_owner(httpreq.state.user, db_task)
    if params is None:
        params = TaskParams()
    taskscheduler.run_task.delay(task_name, params.model_dump_json())
    return {"status": "ok"}


def _export_file_name_conflicts(
    candidate: ExportTask, exclude_id: str | None = None
) -> bool:
    """True when another ExportTask has the same name or maps to the same output file."""
    target_file = candidate.file_name
    for existing in ExportTask.list():
        if exclude_id and existing.id == exclude_id:
            continue
        if existing.name == candidate.name or existing.file_name == target_file:
            return True
    return False


@router.post(
    "/{task_name}/toggle",
    dependencies=[Depends(GetCurrentUserWithPermissions(admin=True))],
)
def toggle(task_name: str) -> TaskTypes:
    """Toggles the enabled status on a task."""
    db_task = Task.find(name=task_name)
    if not db_task:
        raise HTTPException(status_code=404, detail=f"Task {task_name} not found")
    db_task.enabled = not db_task.enabled
    db_task.save()
    return cast("TaskTypes", db_task)


@router.post("/search")
def search(request: TaskSearchRequest) -> TaskSearchResponse:
    """Searches for tasks."""
    query = request.query
    if request.type:
        query["type"] = request.type
    tasks, total = Task.filter(
        query,
        offset=request.page * request.count,
        count=request.count,
        sorting=request.sorting,
    )
    return TaskSearchResponse(tasks=tasks, total=total)


@router.post("/export/new")
@rbac.global_permission(roles.Permission.WRITE)
def new_export(httpreq: Request, request: NewExportRequest) -> ExportTask:
    """Creates a new ExportTask in the database."""
    if _export_file_name_conflicts(request.export):
        raise HTTPException(
            status_code=409,
            detail=f"ExportTask {request.export.name} conflicts with an existing export name or output file",
        )
    template = Template.find(name=request.export.template_name)
    if not template:
        raise HTTPException(
            status_code=404,
            detail=f"ExportTask could not be created: Template {request.export.template_name} not found",
        )
    request.export.owner = httpreq.state.user.username
    export = request.export.save()
    return export


@router.patch("/export/{export_name}")
@rbac.global_permission(roles.Permission.WRITE)
def patch_export(
    httpreq: Request, export_name: str, request: PatchExportRequest
) -> ExportTask:
    """Patches an existing ExportTask in the database."""
    db_export = ExportTask.find(name=export_name)
    if not db_export:
        raise HTTPException(
            status_code=404, detail=f"ExportTask {export_name} not found"
        )
    _require_export_owner(httpreq.state.user, db_export)

    template = Template.find(name=request.export.template_name)
    if not template:
        raise HTTPException(
            status_code=422,
            detail=f"ExportTask could not be patched: Template {request.export.template_name} not found",
        )

    update_data = request.export.model_dump(exclude_unset=True, exclude={"owner"})
    updated_export = db_export.model_copy(update=update_data)
    if _export_file_name_conflicts(updated_export, exclude_id=db_export.id):
        raise HTTPException(
            status_code=409,
            detail=f"ExportTask {updated_export.name} conflicts with an existing export name or output file",
        )
    new = updated_export.save()
    return new


@router.get("/export/{export_id}/content")
def export_content(httpreq: Request, export_id: str) -> StreamingResponse:
    """Downloads the latest contents of a given ExportTask."""
    export = ExportTask.get(export_id)
    if not export:
        raise HTTPException(status_code=404, detail=f"ExportTask {export_id} not found")
    _require_export_owner(httpreq.state.user, export)
    return StreamingResponse(
        io.BytesIO(export.file_contents),
        headers={
            "Cache-Control": "no-cache",
            "Content-Disposition": f"attachment; filename={export.file_name}",
        },
    )


@router.delete("/export/{export_name}")
@rbac.global_permission(roles.Permission.WRITE)
def delete_export(httpreq: Request, export_name: str) -> dict[str, str]:
    """Deletes an ExportTask."""
    export = ExportTask.find(name=export_name)
    if not export:
        raise HTTPException(
            status_code=404, detail=f"ExportTask {export_name} not found"
        )
    _require_export_owner(httpreq.state.user, export)
    export.delete()
    return {"status": "ok"}
