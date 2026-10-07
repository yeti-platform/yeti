from collections.abc import Mapping

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict

from core.config.config import yeti_config
from core.schemas import dfiq, entity, indicator, observable
from core.taskscheduler import app
from core.web.apiv2.auth import get_current_active_user

# API endpoints
router = APIRouter()

_OBSERVABLE_LABELS = {
    "generic": "Generic observable",
    "ipv6": "IPv6",
    "ipv4": "IPv4",
    "hostname": "Hostname",
    "url": "Url",
    "file": "File",
    "sha256": "SHA256",
    "md5": "MD5",
    "sha1": "SHA1",
    "asn": "ASN",
    "wallet": "Wallet",
    "certificate": "Certificate",
    "cidr": "CIDR",
    "mac_address": "Mac Address",
    "command_line": "Command Line",
    "registry_key": "Registry Key",
    "imphash": "Imphash",
    "tlsh": "TLSH",
    "ssdeep": "SSDEEP",
    "email": "Email",
    "path": "Filesystem path",
    "container_image": "Container Image",
    "docker_image": "Docker Image",
    "user_agent": "User-Agent",
    "user_account": "User Account",
    "iban": "IBAN",
    "bic": "BIC",
    "auth_secret": "Auth Secret",
    "ja3": "JA3",
    "jarm": "JARM",
    "mutex": "Mutex",
    "named_pipe": "Named Pipe",
    "package": "Package",
}

_ENTITY_LABELS = {
    "investigation": "Investigation",
    "malware": "Malware",
    "tool": "Tool",
    "attack-pattern": "Attack pattern",
    "threat-actor": "Threat actor",
    "intrusion-set": "Intrusion set",
    "campaign": "Campaign",
    "identity": "Identity",
    "company": "Company",
    "vulnerability": "Vulnerability",
    "course-of-action": "Course of action",
    "note": "Note",
}

_INDICATOR_LABELS = {
    "forensicartifact": "Forensic artifact",
    "regex": "Regular expression",
    "query": "Query",
    "yara": "Yara",
    "suricata": "Suricata",
    "sigma": "Sigma",
}

_DFIQ_LABELS = {
    "scenario": "Scenario",
    "facet": "Facet",
    "question": "Question",
}


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


class TypeEntry(BaseModel):
    """A single creatable object type."""

    type: str
    label: str


class SystemTypesResponse(BaseModel):
    """Available object types per family, for the frontend's creation UI."""

    observables: list[TypeEntry]
    entities: list[TypeEntry]
    indicators: list[TypeEntry]
    dfiq: list[TypeEntry]


def _type_entries(
    type_mapping: Mapping[str, type], base_class: type, labels: dict[str, str]
) -> list[TypeEntry]:
    """Turns a family's TYPE_MAPPING into a sorted list of API-facing entries.

    Skips the alias keys (e.g. "observable"/"observables") that TYPE_MAPPING
    maps back to the family's own base class rather than a concrete leaf type.
    """
    entries = [
        TypeEntry(
            type=type_str,
            label=labels.get(type_str)
            or type_str.replace("_", " ").replace("-", " ").title(),
        )
        for type_str, cls in type_mapping.items()
        if cls is not base_class
    ]
    return sorted(entries, key=lambda entry: entry.label)


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


@router.get("/types", dependencies=[Depends(get_current_active_user)])
def get_system_types() -> SystemTypesResponse:
    """Lists every creatable object type, grouped by family.

    Derived from each family's TYPE_MAPPING rather than a hand-maintained
    list, so it automatically includes plugin-registered private/custom
    types and can't drift from what the backend actually supports.
    """
    return SystemTypesResponse(
        observables=_type_entries(
            observable.TYPE_MAPPING, observable.Observable, _OBSERVABLE_LABELS
        ),
        entities=_type_entries(entity.TYPE_MAPPING, entity.Entity, _ENTITY_LABELS),
        indicators=_type_entries(
            indicator.TYPE_MAPPING, indicator.Indicator, _INDICATOR_LABELS
        ),
        dfiq=_type_entries(dfiq.TYPE_MAPPING, dfiq.DFIQBase, _DFIQ_LABELS),
    )


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
