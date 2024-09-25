import io

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict

from core import taskscheduler
from core.schemas.task import ExportTask, Task, TaskParams, TaskType, TaskTypes
from core.schemas.template import Template


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

    tasks: list[TaskTypes]
    total: int


class NewExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    export: ExportTask


class PatchExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    export: ExportTask


# API endpoints
router = APIRouter()


@router.post("/{task_name}/run")
async def run(task_name, params: TaskParams | None = None) -> dict:
    """Runs a task asynchronously."""
    if params is None:
        params = TaskParams()
    taskscheduler.run_task.delay(task_name, params.model_dump_json())
    return {"status": "ok"}


@router.post("/{task_name}/toggle")
async def toggle(task_name) -> TaskTypes:
    """Toggles the enabled status on a task."""
    db_task: Task = Task.find(name=task_name)  # type: ignore
    db_task.enabled = not db_task.enabled
    db_task.save()
    return db_task


@router.post("/search")
async def search(request: TaskSearchRequest) -> TaskSearchResponse:
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
async def new_export(request: NewExportRequest) -> ExportTask:
    """Creates a new ExportTask in the database."""
    template = Template.find(name=request.export.template_name)
    if not template:
        raise HTTPException(
            status_code=404,
            detail=f"ExportTask could not be created: Template {request.export.template_name} not found",
        )
    export = request.export.save()
    return export


@router.patch("/export/{export_name}")
async def patch_export(request: PatchExportRequest) -> ExportTask:
    """Pathes an existing ExportTask in the database."""
    db_export = ExportTask.find(name=request.export.name)
    if not db_export:
        raise HTTPException(
            status_code=404, detail=f"ExportTask {request.export.name} not found"
        )

    template = Template.find(name=request.export.template_name)
    if not template:
        raise HTTPException(
            status_code=422,
            detail=f"ExportTask could not be patched: Template {request.export.template_name} not found",
        )

    update_data = request.export.model_dump(exclude_unset=True)
    updated_export = db_export.model_copy(update=update_data)
    new = updated_export.save()
    return new


@router.get("/export/{export_id}/content")
async def export_content(export_id: str):
    """Downloads the latest contents of a given ExportTask."""
    export = ExportTask.get(export_id)
    if not export:
        raise HTTPException(status_code=404, detail=f"ExportTask {export_id} not found")
    return StreamingResponse(
        io.BytesIO(export.file_contents),
        headers={
            "Cache-Control": "no-cache",
            "Content-Disposition": f"attachment; filename={export.file_name}",
        },
    )


@router.delete("/export/{export_name}")
async def delete_export(export_name: str):
    """Deletes an ExportTask."""
    export = ExportTask.find(name=export_name)
    if not export:
        raise HTTPException(
            status_code=404, detail=f"ExportTask {export_name} not found"
        )
    export.delete()
    return {"status": "ok"}
