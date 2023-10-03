import datetime
import os
from typing import Iterable

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from core import taskmanager
from core.schemas.task import (TYPE_MAPPING, ExportTask, Task, TaskType,
                               TaskTypes)
from core.schemas.template import Template

# Request schemas
class TaskSearchRequest(BaseModel):
    name: str | None = None
    type: TaskType | None = None
    count: int = 50
    page: int = 0

class TaskSearchResponse(BaseModel):
    tasks: list[TaskTypes]
    total: int

class NewExportRequest(BaseModel):
    export: ExportTask

class PatchExportRequest(BaseModel):
    export: ExportTask

# API endpoints
router = APIRouter()

@router.post('/{task_name}/run')
async def run(task_name):
    """Runs a task asynchronously."""
    taskmanager.run_task.delay(task_name)
    return {"status": "ok"}

@router.post('/{task_name}/toggle')
async def toggle(task_name) -> TaskTypes:
    """Toggles the enabled status on a task."""
    db_task: Task = Task.find(name=task_name)  # type: ignore
    db_task.enabled = not db_task.enabled
    db_task.save()
    return db_task

@router.post('/search')
async def search(request: TaskSearchRequest) -> TaskSearchResponse:
    """Searches for tasks."""
    request_args = request.model_dump()
    count = request_args.pop('count')
    page = request_args.pop('page')
    tasks, total = Task.filter(request_args, offset=request.page*request.count, count=request.count)
    return TaskSearchResponse(tasks=tasks, total=total)

@router.post('/export/new')
async def new_export(request: NewExportRequest) -> ExportTask:
    """Creates a new ExportTask in the database."""
    template = Template.find(name=request.export.template_name)
    if not template:
        raise HTTPException(
            status_code=404,
            detail=f"ExportTask could not be created: Template {request.export.template_name} not found")
    export = request.export.save()
    return export

@router.patch('/export/{export_name}')
async def patch_export(request: PatchExportRequest) -> ExportTask:
    """Pathes an existing ExportTask in the database."""
    db_export = ExportTask.find(name=request.export.name)
    if not db_export:
        raise HTTPException(
            status_code=404,
            detail=f"ExportTask {request.export.name} not found")

    template = Template.find(name=request.export.template_name)
    if not template:
        raise HTTPException(
            status_code=422,
            detail=f"ExportTask could not be patched: Template {request.export.template_name} not found")

    update_data = request.export.model_dump(exclude_unset=True)
    updated_export = db_export.model_copy(update=update_data)
    new = updated_export.save()
    return new

@router.get('/export/{export_name}/content')
async def export_content(export_name: str):
    """Downloads the latest contents of a given ExportTask."""
    export = ExportTask.find(name=export_name)
    if not export:
        raise HTTPException(
            status_code=404, detail=f"ExportTask {export_name} not found")

    directory = export.output_dir
    filepath = os.path.join(directory, export.name)
    return FileResponse(filepath)
