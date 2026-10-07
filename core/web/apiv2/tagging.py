from typing import Callable, Type, TypeVar

from fastapi import HTTPException, Request

from core.schemas import audit, model

T = TypeVar("T")


def tag_objects(
    base_type: Type[T],
    httpreq: Request,
    ids: list[str],
    tags: list[str],
    strict: bool,
    not_found_status_code: int,
    not_found_detail: Callable[[str], str],
) -> tuple[int, dict[str, dict[str, model.YetiTagInstance]]]:
    """Tags a set of arbitrary Yeti Objects, individually or in bulk."""
    objects = []
    for object_id in ids:
        obj = base_type.get(object_id)  # ty: ignore[unresolved-attribute]
        if not obj:
            raise HTTPException(
                status_code=not_found_status_code, detail=not_found_detail(object_id)
            )
        objects.append(obj)

    object_tags = {}
    for obj in objects:
        old_tags = [t.name for t in obj.get_tags().values()]
        obj = obj.tag(tags, clear=strict)
        audit.log_timeline_tags(httpreq.state.username, obj, old_tags)
        object_tags[obj.extended_id] = {t.name: t for t in obj.tags}

    return len(objects), object_tags
