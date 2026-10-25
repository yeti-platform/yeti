import logging

import requests
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from core.config.config import yeti_config


class BloomSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    values: list[str]


class BloomHit(BaseModel):
    value: str
    hits: list[str]


logger = logging.getLogger(__name__)

# API endpoints
router = APIRouter()

BLOOMCHECK_ENDPOINT = yeti_config.get("bloom", "bloomcheck_endpoint")


def check_bloomcheck_endpoint():
    """Ensure BLOOMCHECK_ENDPOINT is set."""
    if not BLOOMCHECK_ENDPOINT:
        raise HTTPException(
            status_code=503,
            detail="bloomcheck endpoint not set in config",
        )
    return BLOOMCHECK_ENDPOINT


@router.post("/search")
def search(
    httpreq: Request,
    request: BloomSearchRequest,
    bloomcheck_endpoint: str = Depends(check_bloomcheck_endpoint),
) -> list[BloomHit]:
    """Checks the bloomcheck microservice for hits."""
    try:
        response = requests.post(
            f"{bloomcheck_endpoint}/check",
            json={"values": request.values, "filters": []},
        )
    except requests.ConnectionError as e:
        # The exception names internal hosts and ports; that belongs in the log,
        # not in a message the UI shows to an analyst.
        logger.warning(
            "Cannot reach the bloomcheck service at %s: %s", bloomcheck_endpoint, e
        )
        raise HTTPException(
            status_code=503,
            detail="Bloom check unavailable: cannot reach the bloomcheck service",
        )
    if response.status_code != 200:
        logger.warning(
            "bloomcheck answered HTTP %s: %s", response.status_code, response.text
        )
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Bloom check failed: bloomcheck answered HTTP {response.status_code}",
        )

    data = response.json()
    if not data:
        return []
    return [BloomHit(**hit) for hit in data]


@router.post("/search/raw")
async def search_raw(
    httpreq: Request, bloomcheck_endpoint: str = Depends(check_bloomcheck_endpoint)
) -> list[BloomHit]:
    """Checks the bloomcheck microservice for hits."""
    values = await httpreq.body()
    try:
        response = requests.post(
            f"{bloomcheck_endpoint}/check/raw",
            data=values,
        )
    except requests.ConnectionError as e:
        # The exception names internal hosts and ports; that belongs in the log,
        # not in a message the UI shows to an analyst.
        logger.warning(
            "Cannot reach the bloomcheck service at %s: %s", bloomcheck_endpoint, e
        )
        raise HTTPException(
            status_code=503,
            detail="Bloom check unavailable: cannot reach the bloomcheck service",
        )
    if response.status_code != 200:
        logger.warning(
            "bloomcheck answered HTTP %s: %s", response.status_code, response.text
        )
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Bloom check failed: bloomcheck answered HTTP {response.status_code}",
        )

    data = response.json()
    if not data:
        return []
    return [BloomHit(**hit) for hit in data]
