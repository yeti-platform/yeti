from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from core.schemas import audit, rbac, roles
from core.schemas.agent_persona import AgentPersona

router = APIRouter()


class NewPersonaRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    persona: AgentPersona


class PatchPersonaRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    persona: AgentPersona


class PersonaSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = ""
    enabled: bool | None = None
    count: int = 50
    page: int = 0


class PersonaSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    personas: list[AgentPersona]
    total: int


def _clear_other_defaults(persona: AgentPersona) -> None:
    """Leaves `persona` as the only default."""
    others, _ = AgentPersona.filter(query_args={"default": True}, count=0)
    for other in others:
        if other.id == persona.id:
            continue
        other.default = False
        other.save()


@router.post("/")
@rbac.global_permission(roles.Permission.WRITE)
def new(httpreq: Request, request: NewPersonaRequest) -> AgentPersona:
    """Creates a new agent persona."""
    if AgentPersona.find(name=request.persona.name):
        raise HTTPException(
            status_code=409,
            detail=f"Persona {request.persona.name} already exists",
        )

    persona = request.persona.save()
    if persona.default:
        _clear_other_defaults(persona)
    rbac.set_acls(persona, user=httpreq.state.user)
    audit.log_timeline(httpreq.state.username, persona)
    return persona


@router.patch("/{id}")
@rbac.permission_on_target(roles.Permission.WRITE)
def patch(httpreq: Request, request: PatchPersonaRequest, id: str) -> AgentPersona:
    """Updates an agent persona."""
    existing = AgentPersona.get(id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Persona {id} not found")

    update = request.persona.model_dump(exclude={"id", "created"})
    persona = existing.model_copy(update=update).save()
    if persona.default:
        _clear_other_defaults(persona)
    audit.log_timeline(httpreq.state.username, persona, old=existing)
    return persona


@router.get("/{id}")
@rbac.permission_on_target(roles.Permission.READ)
def details(httpreq: Request, id: str) -> AgentPersona:
    """Returns a single agent persona."""
    persona = AgentPersona.get(id)
    if not persona:
        raise HTTPException(status_code=404, detail=f"Persona {id} not found")
    return persona


@router.delete("/{id}")
@rbac.permission_on_target(roles.Permission.WRITE)
def delete(httpreq: Request, id: str) -> None:
    """Deletes an agent persona. The default one cannot be deleted."""
    persona = AgentPersona.get(id)
    if not persona:
        raise HTTPException(status_code=404, detail=f"Persona {id} not found")
    if persona.default:
        raise HTTPException(
            status_code=409,
            detail="Cannot delete the default persona; mark another as default first",
        )
    persona.delete()


@router.post("/search")
def search(httpreq: Request, request: PersonaSearchRequest) -> PersonaSearchResponse:
    """Searches for agent personas."""
    query: dict = {"name": request.name}
    if request.enabled is not None:
        query["enabled"] = request.enabled

    personas, total = AgentPersona.filter(
        query_args=query,
        offset=request.page * request.count,
        count=request.count,
        user=httpreq.state.user,
    )
    return PersonaSearchResponse(personas=personas, total=total)
