from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from core.schemas import audit, rbac, roles

router = APIRouter()


class NewGroupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str | None = None


class PatchGroupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rbacgroup: rbac.Group


class GroupSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = ""
    permissions: roles.Permission | None = None
    count: int = 50
    page: int = 0


class GroupSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    groups: list[rbac.Group]
    total: int


@router.get("/{id}")
@rbac.permission_on_target(roles.Permission.READ)
def get(httpreq: Request, id: str) -> rbac.Group:
    # We use filter because we want the ACL graph query
    groups, total = rbac.Group.filter(
        query_args={"_id": f"groups/{id}"},
        offset=0,
        count=1,
        user=httpreq.state.user,
        graph_queries=[("acls", "acls", "inbound", "username")],
    )
    if not groups:
        raise HTTPException(status_code=404, detail=f"Group {id} not found")
    return groups[0]


@router.post("")
@rbac.global_permission(roles.Permission.WRITE)
def new(httpreq: Request, request: NewGroupRequest) -> rbac.Group:
    existing = rbac.Group.find(name=request.name)
    if existing:
        raise HTTPException(
            status_code=409, detail=f"Group {request.name} already exists"
        )
    group = rbac.Group(name=request.name, description=request.description).save()
    rbac.set_acls(group, user=httpreq.state.user)
    audit.log_timeline(httpreq.state.username, group)
    return group


@router.post("/search")
def search(httpreq: Request, request: GroupSearchRequest) -> GroupSearchResponse:
    query = {
        "name": request.name,
    }
    groups, total = rbac.Group.filter(
        query_args=query,
        offset=request.page * request.count,
        count=request.count,
        user=httpreq.state.user,
        graph_queries=[("acls", "acls", "inbound", "username")],
    )
    return GroupSearchResponse(groups=groups, total=total)


@router.patch("/{id}")
@rbac.permission_on_target(roles.Permission.WRITE)
def patch(httpreq: Request, id: str, request: PatchGroupRequest) -> rbac.Group:
    db_group = rbac.Group.get(id)
    if db_group is None:
        raise HTTPException(status_code=404, detail="Group not found")
    update_data = request.rbacgroup.model_dump(exclude_unset=True)
    updated_group = db_group.model_copy(update=update_data)
    new = updated_group.save()
    audit.log_timeline(httpreq.state.username, new, old=db_group)
    return new


@router.delete("/{id}")
@rbac.permission_on_target(roles.Permission.DELETE)
def delete(httpreq: Request, id: str) -> None:
    if not (
        httpreq.state.user.has_permissions(f"groups/{id}", roles.Permission.DELETE)
        or httpreq.state.user.admin
    ):
        raise HTTPException(status_code=403, detail="Forbidden")
    db_group = rbac.Group.get(id)
    if db_group is None:
        raise HTTPException(status_code=404, detail="Group not found")
    db_group.delete()
    audit.log_timeline(httpreq.state.username, db_group, action="delete")
