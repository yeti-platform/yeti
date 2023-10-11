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
    system: dict


@router.get("/config")
async def get_config() -> SystemConfig:
    """Gets the system config."""
    config = SystemConfig(
        auth=yeti_config.get('auth'),
        arangodb=yeti_config.get('arangodb'),
        redis=yeti_config.get('redis'),
        proxy=yeti_config.get('proxy'),
        system=yeti_config.get('system'),
    )
    return config
