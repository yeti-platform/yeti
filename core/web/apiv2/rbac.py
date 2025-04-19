from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from core.schemas import dfiq, entity, graph, indicator, observable, rbac, roles, user

router = APIRouter()


class RBACIdentity(BaseModel):
    id: str
    type: str


class UpdateACLRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ids: list[RBACIdentity]
    role: roles.Permission = roles.Role.READER


class UpdateMembersResponse(BaseModel):
    updated: int
    failed: int


TYPE_TO_MODEL_MAPPING = {
    "entity": entity.Entity,
    "rbacgroup": rbac.Group,
    "indicator": indicator.Indicator,
    "user": user.User,
    "dfiq": dfiq.DFIQBase,
    "observable": observable.Observable,
}

EXTENDED_ID_MAPPING = {
    "entity": "entities",
    "rbacgroup": "groups",
    "indicator": "indicators",
    "user": "users",
    "dfiq": "dfiq",
    "observable": "observables",
}


@router.get("/{type}/{id}")
def get_acl_details(httpreq: Request, type: str, id: str):
    if type not in TYPE_TO_MODEL_MAPPING:
        raise HTTPException(
            status_code=400,
            detail=f"Type must be one of {TYPE_TO_MODEL_MAPPING.keys()}",
        )
    if not httpreq.state.user.has_permissions(
        f"{EXTENDED_ID_MAPPING[type]}/{id}", roles.Role.OWNER
    ):
        raise HTTPException(
            status_code=403, detail="Missing permissions READER on target"
        )

    YetiObjectType = TYPE_TO_MODEL_MAPPING[type]

    db_entity = YetiObjectType.get(id)
    if not db_entity:
        raise HTTPException(status_code=404, detail=f"{type} {id} not found")

    db_entity.get_acls(direct=True)
    return db_entity


@router.post("/{type}/{id}/update-members")
def update_member(
    httpreq: Request, type: str, id: str, request: UpdateACLRequest
) -> UpdateMembersResponse:
    if type not in TYPE_TO_MODEL_MAPPING:
        raise HTTPException(
            status_code=400,
            detail=f"Type must be one of {TYPE_TO_MODEL_MAPPING.keys()}",
        )
    if not httpreq.state.user.has_permissions(
        f"{EXTENDED_ID_MAPPING[type]}/{id}", roles.Role.OWNER
    ):
        raise HTTPException(
            status_code=403, detail="Missing permissions OWNER on target"
        )

    YetiObjectType = TYPE_TO_MODEL_MAPPING[type]

    db_entity = YetiObjectType.get(id)
    if not db_entity:
        raise HTTPException(status_code=404, detail=f"{type} {id} not found")
    updated = 0
    failed = 0
    for identity in request.ids:
        if identity.id == httpreq.state.user.id and request.role != roles.Role.OWNER:
            failed += 1
            continue
        db_identity = None
        if identity.type == "group":
            db_identity = rbac.Group.get(identity.id)
        if identity.type == "user":
            db_identity = user.User.get(identity.id)
        if not db_identity:
            failed += 1
            continue

        db_identity.link_to_acl(db_entity, request.role)
        updated += 1
    return UpdateMembersResponse(updated=updated, failed=failed)


@router.delete("/{id}")
def delete(httpreq: Request, id: str) -> None:
    """Deletes an Entity."""
    relationship = graph.RoleRelationship.get(id)
    if not relationship:
        raise HTTPException(status_code=404, detail=f"Relationship ID {id} not found")
    relationship.delete()
