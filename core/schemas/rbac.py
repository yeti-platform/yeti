import logging
import re
from functools import wraps
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from fastapi import HTTPException, Request, status
from pydantic import computed_field

from core import database_arango
from core.config.config import yeti_config
from core.schemas import roles
from core.schemas.model import YetiAclModel

logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from core.schemas import user

RBAC_ENABLED = yeti_config.get("rbac", "enabled", default=False)


class Group(YetiAclModel, database_arango.ArangoYetiConnector):
    _collection_name: ClassVar[str] = "groups"
    _root_type: Literal["rbacgroup"] = "rbacgroup"

    name: str
    description: str | None = None

    @classmethod
    def load(cls, object: dict) -> "Group":
        return cls(**object)

    @computed_field(return_type=Literal["rbacgroup"])
    @property
    def root_type(self):
        return self._root_type


def permission_on_target(permission: roles.Permission):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, httpreq: Request, **kwargs):
            if not RBAC_ENABLED or httpreq.state.user.admin:
                return func(*args, httpreq=httpreq, **kwargs)

            if extended_id := re.search(
                f"/api/v2/(\\w+/{kwargs['id']})", httpreq.scope["path"]
            ):
                extended_id = extended_id.group(1)
            if not httpreq.state.user.has_permissions(extended_id, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Forbidden: missing privileges {permission} on target",
                )
            return func(*args, httpreq=httpreq, **kwargs)

        return wrapper

    return decorator


def permission_on_ids(permission: roles.Permission):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, httpreq: Request, **kwargs):
            ids: list[str] = kwargs["request"].ids
            if not RBAC_ENABLED or httpreq.state.user.admin:
                return func(*args, httpreq=httpreq, **kwargs)

            prefix = re.search(r"/api/v2/(\w+)", httpreq.scope["path"]).group(1)
            for id in ids:
                extended_id = f"{prefix}/{id}"
                if not httpreq.state.user.has_permissions(extended_id, permission):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Forbidden: missing privileges {permission} on target {extended_id}",
                    )

            return func(*args, httpreq=httpreq, **kwargs)

        return wrapper

    return decorator


def global_permission(permission: roles.Permission):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, httpreq: Request, **kwargs):
            if not RBAC_ENABLED or httpreq.state.user.admin:
                return func(*args, httpreq=httpreq, **kwargs)
            if httpreq.state.user.global_role & permission == permission:
                return func(*args, httpreq=httpreq, **kwargs)

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: missing global permission {permission}",
            )

        return wrapper

    return decorator


def set_acls(yeti_object: Any, user: "user.User | None" = None, set_default=True):
    """Sets the ACLs for a given object taking system defaults into account.

    Args:
        user: The user to set the default ACLs for.
        yeti_object: The object to set the default ACLs for.
        set_default: If True, set the default ACLs.
    """
    access = False
    if user:
        user.link_to_acl(yeti_object, roles.Role.OWNER)
        access = True

    if set_default:
        default_acls = yeti_config.get("rbac", "default_acls", default="none")
        if default_acls == "none":
            logger.warning("No default ACLs set, setting to user only.")
            return
        for identity in default_acls.split(","):
            group = Group.find(name=identity)
            if group:
                group.link_to_acl(yeti_object, roles.Role.OWNER)
                access = True
            else:
                logger.warning(f"Default ACL group {identity} not found.")

    if not access:
        logger.warning("No default ACLs set, object is only accessible by admin!")
