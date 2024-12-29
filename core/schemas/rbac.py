import datetime
import re
from enum import Enum
from functools import wraps
from typing import ClassVar, List, Literal, Optional

from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict, computed_field

from core import database_arango
from core.schemas.model import YetiBaseModel


class Group(YetiBaseModel, database_arango.ArangoYetiConnector):
    _collection_name: ClassVar[str] = "groups"
    name: str
    description: str | None = None
    _root_type: Literal["rbacgroup"] = "rbacgroup"

    @classmethod
    def load(cls, object: dict) -> "Group":
        return cls(**object)

    @computed_field(return_type=Literal["rbacgroup"])
    @property
    def root_type(self):
        return self._root_type


def permission_on_target(permission: int):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, httpreq: Request, **kwargs):
            if extended_id := re.search(
                f'/api/v2/(\\w+/{kwargs["id"]})', httpreq.scope["path"]
            ):
                extended_id = extended_id.group(1)
            if not httpreq.state.user.has_role(extended_id, permission):
                raise HTTPException(status_code=403, detail="Forbidden")
            return func(*args, httpreq=httpreq, **kwargs)

        return wrapper

    return decorator


def permission_on_ids(permission: int):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, httpreq: Request, **kwargs):
            ids: list[str] = kwargs["request"].ids
            prefix = re.search(r"/api/v2/(\w+)", httpreq.scope["path"]).group(1)
            for id in ids:
                extended_id = f"{prefix}/{id}"
                if not httpreq.state.user.has_role(extended_id, permission):
                    raise HTTPException(status_code=403, detail="Forbidden")
            return func(*args, httpreq=httpreq, **kwargs)

        return wrapper

    return decorator


def global_permission(permission: int):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, httpreq: Request, **kwargs):
            if not httpreq.state.user.has_role("global", permission):
                raise HTTPException(status_code=403, detail="Forbidden")
            return func(*args, httpreq=httpreq, **kwargs)

        return wrapper

    return decorator
