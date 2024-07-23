import logging

from fastapi import APIRouter, Depends, FastAPI, Request
from starlette.middleware.sessions import SessionMiddleware

from core.config.config import yeti_config
from core.logger import logger
from core.web.apiv2 import (
    auth,
    dfiq,
    entities,
    graph,
    import_data,
    indicators,
    observables,
    system,
    tag,
    tasks,
    templates,
    users,
)

SECRET_KEY = yeti_config.get("auth", "secret_key")

app = FastAPI()

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["auth"])

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

LOGGING_EXCLUDELIST = ["/auth/"]
LOGGING_SENSITIVE_BODY = [
    "/users/",
]
LOG_BODY_SIZE_LIMIT = 2000
CONTENT_TOO_LARGE_MESSAGE = f"[Request body > {LOG_BODY_SIZE_LIMIT} bytes, not logged]"


@app.middleware("http")
async def log_requests(request: Request, call_next):
    req_body = await request.body()
    response = await call_next(request)
    # Do not log auth-related requests
    for path in LOGGING_EXCLUDELIST:
        if path in request.url.path:
            return response
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
            if len(req_body) > LOG_BODY_SIZE_LIMIT:
                extra["body"] = CONTENT_TOO_LARGE_MESSAGE.encode("utf-8")
            else:
                extra["body"] = req_body

        for path in LOGGING_SENSITIVE_BODY:
            if path in request.url.path:
                extra["body"] = b""

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
