from typing import Type, TypeVar

from fastapi import HTTPException, Request

from core.schemas import audit

T = TypeVar("T")


def get_details(base_type: Type[T], id: str, not_found_detail: str) -> T:
    """Returns full details (tags and ACLs included) for a single object."""
    obj = base_type.get(id)  # ty: ignore[unresolved-attribute]
    if not obj:
        raise HTTPException(status_code=404, detail=not_found_detail)
    obj.get_tags()
    obj.get_acls()
    return obj


def delete_object(
    base_type: Type[T], httpreq: Request, id: str, not_found_detail: str
) -> None:
    """Deletes a single object by id, recording an audit-log delete event."""
    obj = base_type.get(id)  # ty: ignore[unresolved-attribute]
    if not obj:
        raise HTTPException(status_code=404, detail=not_found_detail)
    audit.log_timeline(httpreq.state.username, obj, action="delete")
    obj.delete()
