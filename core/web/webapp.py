from fastapi import FastAPI
from fastapi import APIRouter

from core.web.apiv2 import observables
from core.web.apiv2 import entities
from core.web.apiv2 import indicators
from core.web.apiv2 import tag
from core.web.apiv2 import graph
from core.web.apiv2 import auth
from core.web.apiv2 import tasks
from core.web.apiv2 import templates
from core.web.apiv2 import users
from core.web.apiv2 import system

app = FastAPI()
api_router = APIRouter()

api_router.include_router(
    observables.router, prefix="/observables", tags=["observables"]
)
api_router.include_router(entities.router, prefix="/entities", tags=["entities"])
api_router.include_router(indicators.router, prefix="/indicators", tags=["indicators"])
api_router.include_router(tag.router, prefix="/tags", tags=["tags"])
api_router.include_router(tasks.router, prefix="/tasks", tags=["tasks"])
api_router.include_router(graph.router, prefix="/graph", tags=["graph"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(templates.router, prefix="/templates", tags=["templates"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(system.router, prefix="/system", tags=["system"])

app.include_router(api_router, prefix="/api/v2")
