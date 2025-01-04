from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from core.schemas import audit, graph, rbac
from core.schemas.rbac import global_permission, permission_on_ids, permission_on_target
from core.schemas.user import User, UserSensitive
from core.web.apiv2.auth import GetCurrentUserWithPermissions, get_current_user

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
    permissions: graph.Permission | None = None
    count: int = 50
    page: int = 0


class GroupSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    groups: list[rbac.Group]
    total: int


@router.post("")
@global_permission(graph.Permission.WRITE)
def new(httpreq: Request, request: NewGroupRequest):
    group = rbac.Group(name=request.name, description=request.description).save()
    httpreq.state.user.link_to_acl(group, graph.Role.OWNER)
    return group


@router.post("/search")
def search(httpreq: Request, request: GroupSearchRequest):
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
@permission_on_target(graph.Permission.WRITE)
def patch(httpreq: Request, id: str, request: PatchGroupRequest):
    db_group = rbac.Group.get(id)
    if db_group is None:
        raise HTTPException(status_code=404, detail="Group not found")
    update_data = request.rbacgroup.model_dump(exclude_unset=True)
    updated_group = db_group.model_copy(update=update_data)
    new = updated_group.save()
    audit.log_timeline(httpreq.state.username, new, old=db_group)
    return new


@router.delete("/{group_id}")
@permission_on_target(graph.Permission.DELETE)
def delete(httpreq: Request, group_id: str):
    if not (
        httpreq.state.user.has_permissions(
            f"groups/{group_id}", graph.Permission.DELETE
        )
        or httpreq.state.user.admin
    ):
        raise HTTPException(status_code=403, detail="Forbidden")
    db_group = rbac.Group.get(group_id)
    if db_group is None:
        raise HTTPException(status_code=404, detail="Group not found")
    db_group.delete()
