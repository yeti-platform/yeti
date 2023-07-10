from fastapi import APIRouter
from pydantic import BaseModel

from core.schemas.template import Template
from core.config.config import yeti_config

# API endpoints
router = APIRouter()

class SystemConfig(BaseModel):
    """System config template."""
    auth: dict
    arangodb: dict
    redis: dict
    proxy: dict
    logging: dict

@router.get('/config')
async def get_config() -> SystemConfig:
    """Gets the system config."""
    config = SystemConfig(
        auth=yeti_config.auth,
        arangodb=yeti_config.arangodb,
        redis=yeti_config.redis,
        proxy=yeti_config.proxy,
        logging=yeti_config.logging
    )
    return config
