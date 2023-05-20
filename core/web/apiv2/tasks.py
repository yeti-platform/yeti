import datetime
from typing import Iterable

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from core.schemas.task import Task, TaskType, TaskTypes, TYPE_MAPPING
from core import taskmanager

# Request schemas
class TaskSearchRequest(BaseModel):
    name: str | None = None
    type: TaskType | None = None
    count: int = 50
    page: int = 0

class TaskSearchResponse(BaseModel):
    tasks: list[TaskTypes]
    total: int

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
    """Searches for observables."""
    request_args = request.dict()
    count = request_args.pop('count')
    page = request_args.pop('page')
    tasks, total = Task.filter(request_args, offset=request.page*request.count, count=request.count)
    return TaskSearchResponse(tasks=tasks, total=total)
