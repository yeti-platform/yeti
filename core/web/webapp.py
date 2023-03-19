
from fastapi import FastAPI
from fastapi import APIRouter
from mongoengine import connect

from core.web.apiv2 import observables
from core.web.apiv2 import tag
from core.web.apiv2 import graph

from core.config.config import yeti_config


connect(
    yeti_config.mongodb.database,
    host=yeti_config.mongodb.host,
    port=yeti_config.mongodb.port,
    username=yeti_config.mongodb.username,
    password=yeti_config.mongodb.password,
    connect=False,
    tls=False,
)




app = FastAPI()
api_router = APIRouter()


@api_router.get("/")
async def api_root():
    return {"message": "(API) Hello World"}

@app.get("/")
async def root():
    return {"message": "Hello World"}

api_router.include_router(observables.router, prefix="/observables", tags=["observables"])
api_router.include_router(tag.router, prefix="/tags", tags=["tags"])
api_router.include_router(graph.router, prefix="/graph", tags=["graph"])

app.include_router(api_router, prefix="/api/v2")
