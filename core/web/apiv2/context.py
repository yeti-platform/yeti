from typing import Type, TypeVar

from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict

from core.schemas import audit

T = TypeVar("T")


class AddContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: str
    context: dict
    skip_compare: set = set()


class DeleteContextRequest(AddContextRequest):
    pass


class ReplaceContextRequest(BaseModel):
    context: list[dict]


def replace_context(
    base_type: Type[T], httpreq: Request, id: str, request: ReplaceContextRequest
) -> T:
    """Replaces context in an arbitrary Yeti Object."""
    obj = base_type.get(id)
    if not obj:
        raise HTTPException(
            status_code=404, detail=f"{base_type.__name__} {id} not found"
        )

    for item in request.context:
        if "source" not in item:
            raise HTTPException(
                status_code=400, detail=f"Source is required in context {item}"
            )

    old_context = obj.context.copy()
    obj.context = request.context
    refreshed_obj = obj.save()
    obj.context = old_context
    audit.log_timeline(httpreq.state.username, refreshed_obj, old=obj)
    return refreshed_obj


def add_context(
    base_type: Type[T], httpreq: Request, id: str, request: AddContextRequest
) -> T:
    """Adds context to an arbitrary Yeti Object."""
    obj = base_type.get(id)
    if not obj:
        raise HTTPException(
            status_code=404, detail=f"{base_type.__name__} {id} not found"
        )

    old_context = obj.context.copy()
    refreshed_obj = obj.add_context(
        request.source, request.context, skip_compare=request.skip_compare
    )
    obj.context = old_context
    audit.log_timeline(httpreq.state.username, refreshed_obj, old=obj)
    return refreshed_obj


def delete_context(
    base_type: Type[T], httpreq: Request, id: str, request: DeleteContextRequest
) -> T:
    """Deletes context from an arbitrary Yeti Object."""
    obj = base_type.get(id)
    if not obj:
        raise HTTPException(
            status_code=404, detail=f"{base_type.__name__} {id} not found"
        )

    old_context = obj.context.copy()
    refreshed_obj = obj.delete_context(request.source, request.context)
    obj.context = old_context
    audit.log_timeline(httpreq.state.username, refreshed_obj, old=obj)
    return refreshed_obj
