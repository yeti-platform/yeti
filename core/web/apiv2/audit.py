from fastapi import APIRouter, Request

from core.schemas import rbac, roles
from core.schemas.audit import TimelineLog

router = APIRouter()


@router.get("/timeline/{id:path}")
def trail(httpreq: Request, id: str):
    rbac.require_permission(httpreq.state.user, id, roles.Permission.READ)
    # `target_id__in` matches the id exactly (the plain `target_id` key is a
    # `LIKE '%id%'` scan that also returns every object whose key starts with
    # the same digits) and is served by the (target_id, timestamp) index.
    return TimelineLog.filter({"target_id__in": [id]}, sorting=[("timestamp", False)])
