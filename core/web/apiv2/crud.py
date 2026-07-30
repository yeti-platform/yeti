from typing import Type, TypeVar

from fastapi import HTTPException, Request

from core.schemas import audit, rbac, roles

T = TypeVar("T")


def search_objects(
    base_type: Type[T],
    httpreq: Request,
    query: dict,
    type_value: str | None,
    sorting: list[tuple[str, bool]],
    count: int,
    page: int,
    aliases: list[tuple[str, str]] | None = None,
    links_count: bool = False,
) -> tuple[list[T], int]:
    """Runs a filter() search (or a get/multiple-style exact-match query)
    and returns (objects, total)."""
    if type_value:
        query["type"] = type_value
    return base_type.filter(  # ty: ignore[unresolved-attribute]
        query_args=query,
        offset=page * count,
        count=count,
        sorting=sorting,
        aliases=aliases or [],
        links_count=links_count,
        user=httpreq.state.user,
    )


def get_by_lookup(
    base_type: Type[T], httpreq: Request, lookup: dict, not_found_detail: str
) -> T:
    """Finds a single object by an arbitrary lookup (e.g. value or name),
    enforcing read permissions on the result."""
    obj = base_type.find(**lookup)  # ty: ignore[unresolved-attribute]
    if not obj:
        raise HTTPException(status_code=404, detail=not_found_detail)
    obj.get_tags()
    if not rbac.RBAC_ENABLED or httpreq.state.user.admin:
        return obj
    if not httpreq.state.user.has_permissions(obj.extended_id, roles.Permission.READ):
        raise HTTPException(
            status_code=403,
            detail=(
                f"Forbidden: missing privileges {roles.Permission.READ} "
                f"on target {obj.extended_id}"
            ),
        )
    return obj


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
