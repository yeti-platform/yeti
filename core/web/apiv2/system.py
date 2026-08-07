from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict

from core.config.config import yeti_config
from core.taskscheduler import app
from core.web.apiv2.auth import get_current_active_user

from core.schemas import dfiq, entity, indicator, observable
from core.schemas.dfiq import DFIQBase
from core.schemas.entity import Entity
from core.schemas.indicator import Indicator
from core.schemas.observable import Observable

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
    rbac_enabled: bool
    agents_enabled: bool


@router.get("/config")
def get_config() -> SystemConfigResponse:
    """Gets the system config."""
    config = SystemConfigResponse(
        auth={
            "module": yeti_config.get("auth", "module"),
            "enabled": yeti_config.get("auth", "enabled"),
        },
        system=yeti_config.get("system"),
        rbac_enabled=yeti_config.get("rbac", "enabled"),
        agents_enabled=yeti_config.get("agents", "enabled"),
    )
    return config


@router.get("/workers", dependencies=[Depends(get_current_active_user)])
def get_worker_status() -> WorkerStatusResponse:
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
def restart_worker(worker_name: str) -> WorkerRestartResponse:
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

@router.get("/types")
def get_system_types() -> dict[str, list[dict]]:
    return {
        "observables": _get_family_types(observable.TYPE_MAPPING, Observable),
        "entities": _get_family_types(entity.TYPE_MAPPING, Entity),
        "indicators": _get_family_types(indicator.TYPE_MAPPING, Indicator),
        "dfiq": _get_family_types(dfiq.TYPE_MAPPING, DFIQBase),
    }

def _get_family_types(type_mapping: dict, base_cls: type) -> list[dict]:
    types_list = []
    seen_classes = set()

    for type_name, cls in type_mapping.items():
        if cls is base_cls or cls in seen_classes:
            continue
        seen_classes.add(cls)

        fields = {}
        for field_name, field_info in cls.model_fields.items():
            if field_name.startswith("_"):
                continue
            fields[field_name] = {
                "required": field_info.is_required(),
                "description": field_info.description or "",
            }

        label = type_name.replace("_", " ").replace("-", " ").title()
        types_list.append({
            "type": type_name,
            "label": label,
            "fields": fields,
        })

    return sorted(types_list, key=lambda x: x["label"])
