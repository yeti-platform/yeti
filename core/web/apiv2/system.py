from core.config.config import yeti_config
from core.taskscheduler import app
from core.web.apiv2.auth import get_current_active_user
from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict

# API endpoints
router = APIRouter()


class WorkerStatusResponse(BaseModel):
    """Worker status API response."""

    registered: dict[str, list[str]]
    active: list[tuple[str, str]]


class WorkerRestartResponse(BaseModel):
    """Worker restart API response."""

    successes: set[str]
    failures: set[str]


class SystemConfigResponse(BaseModel):
    """System config template."""

    model_config = ConfigDict(extra="forbid")

    auth: dict
    system: dict


@router.get("/config")
async def get_config() -> SystemConfigResponse:
    """Gets the system config."""
    config = SystemConfigResponse(
        auth={
            "module": yeti_config.get("auth", "module"),
            "enabled": yeti_config.get("auth", "enabled"),
        },
        system=yeti_config.get("system"),
    )
    return config


@router.get("/workers", dependencies=[Depends(get_current_active_user)])
async def get_worker_status() -> WorkerStatusResponse:
    inspect = app.control.inspect(timeout=5, destination=None)

    registered = {}
    for host, data in inspect.registered().items():
        registered[host] = data

    active_tasks = []
    for host, tasks in inspect.active().items():
        for task in tasks:
            task_name, params = task["args"]
            active_tasks.append((task_name, params))

    return WorkerStatusResponse(
        registered=registered,
        active=active_tasks,
    )


@router.post(
    "/restartworker/{worker_name}", dependencies=[Depends(get_current_active_user)]
)
async def restart_worker(worker_name: str) -> WorkerRestartResponse:
    """Restarts a single or all Celery workers."""
    destination = [worker_name] if worker_name != "all" else None
    response = app.control.broadcast(
        "pool_restart",
        arguments={"reload": True},
        destination=destination,
        reply=True,
    )

    failures = set()
    successes = set()
    for resp in response:
        for worker, status in resp.items():
            if "ok" not in status:
                failures.add(worker)
            else:
                successes.add(worker)

    return WorkerRestartResponse(
        successes=successes,
        failures=failures,
    )
