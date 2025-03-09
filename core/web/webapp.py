import json
import logging
import os

from fastapi import APIRouter, Depends, FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware

from core.config.config import yeti_config
from core.logger import logger
from core.web.apiv2 import (
    audit,
    auth,
    dfiq,
    entities,
    graph,
    groups,
    import_data,
    indicators,
    observables,
    rbac,
    system,
    tag,
    tasks,
    templates,
    users,
)

SECRET_KEY = yeti_config.get("auth", "secret_key")
if not SECRET_KEY:
    raise RuntimeError("You must set auth.secret_key in the configuration file.")

app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["auth"])

api_router.include_router(audit.router, prefix="/audit", tags=["audit"])

api_router.include_router(
    observables.router,
    prefix="/observables",
    tags=["observables"],
    dependencies=[Depends(auth.get_current_active_user)],
)
api_router.include_router(
    entities.router,
    prefix="/entities",
    tags=["entities"],
    dependencies=[Depends(auth.get_current_active_user)],
)
api_router.include_router(
    indicators.router,
    prefix="/indicators",
    tags=["indicators"],
    dependencies=[Depends(auth.get_current_active_user)],
)
api_router.include_router(
    tag.router,
    prefix="/tags",
    tags=["tags"],
    dependencies=[Depends(auth.get_current_active_user)],
)

api_router.include_router(
    dfiq.router,
    prefix="/dfiq",
    tags=["dfiq"],
    dependencies=[Depends(auth.get_current_active_user)],
)

api_router.include_router(
    tasks.router,
    prefix="/tasks",
    tags=["tasks"],
    dependencies=[Depends(auth.get_current_active_user)],
)
api_router.include_router(
    graph.router,
    prefix="/graph",
    tags=["graph"],
    dependencies=[Depends(auth.get_current_active_user)],
)
api_router.include_router(
    templates.router,
    prefix="/templates",
    tags=["templates"],
    dependencies=[Depends(auth.get_current_active_user)],
)
api_router.include_router(
    users.router,
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(auth.get_current_active_user)],
)

api_router.include_router(
    groups.router,
    prefix="/groups",
    tags=["groups"],
    dependencies=[Depends(auth.get_current_active_user)],
)

api_router.include_router(
    rbac.router,
    prefix="/rbac",
    tags=["rbac"],
    dependencies=[Depends(auth.get_current_active_user)],
)

# Dependencies are set in system endpoints
api_router.include_router(
    system.router,
    prefix="/system",
    tags=["system"],
)

api_router.include_router(
    import_data.router,
    prefix="/import_data",
    tags=["import_data"],
    dependencies=[Depends(auth.get_current_active_user)],
)

app.include_router(api_router, prefix="/api/v2")


@app.middleware("http")
async def log_requests(request: Request, call_next):
    req_body = await request.body()
    response = await call_next(request)
    try:
        extra = {
            "type": "audit.log",
            "path": request.url.path,
            "method": request.method,
            "username": "anonymous",
            # When behind a proxy, we should start uvicorn with --proxy-headers
            # and use request.headers.get('x-forwarded-for') instead.
            "client": request.client.host,
            "status_code": response.status_code,
            "content-type": request.headers.get("content-type", ""),
            "body": b"",
        }
        if getattr(request.state, "username", None):
            extra["username"] = request.state.username
        if req_body:
            extra["body"] = req_body

            # Check if the request body is JSON or form data
            if request.headers.get("content-type", "").startswith(
                "multipart/form-data"
            ):
                try:
                    # Try to parse the request body as form data
                    form_data = await request.form()
                    out = {}

                    # Redact sensitive fields
                    for key, value in form_data.items():
                        out[key] = value

                    extra["body"] = json.dumps(out)
                except Exception:
                    # If parsing fails, just log the request body as is
                    pass
            else:
                try:
                    # Try to parse the request body as JSON
                    json_body = await request.json()
                    extra["body"] = json.dumps(json_body)
                except Exception:
                    # If parsing fails, just log the request body as is
                    pass

        if response.status_code == 200:
            logger.info("Authorized request", extra=extra)
        elif response.status_code == 401:
            logger.warning("Unauthorized request", extra=extra)
        else:
            logger.error("Bad request", extra=extra)
    except Exception:
        err_logger = logging.getLogger("webapp.log_requests")
        err_logger.exception("Error while logging request")
    return response
