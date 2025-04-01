import requests
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from core.config.config import yeti_config


class BloomSearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    values: list[str]


class BloomHit(BaseModel):
    value: str
    hits: list[str]


# API endpoints
router = APIRouter()

BLOOMCHECK_ENDPOINT = yeti_config.get("bloom", "bloomcheck_endpoint")


@router.post("/search")
def search(httpreq: Request, request: BloomSearchRequest) -> list[BloomHit]:
    """Checks the bloomcheck microservice for hits."""
    try:
        response = requests.post(
            f"{BLOOMCHECK_ENDPOINT}/check",
            json={"values": request.values, "filters": []},
        )
    except requests.ConnectionError as e:
        raise HTTPException(
            status_code=503,
            detail=f"Error connecting to bloomcheck: {e}",
        )
    if response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Error fetching bloomcheck: {response.text}",
        )

    data = response.json()
    if not data:
        return []
    return [BloomHit(**hit) for hit in data]


@router.post("/search/raw")
async def search_raw(httpreq: Request) -> list[BloomHit]:
    """Checks the bloomcheck microservice for hits."""
    values = await httpreq.body()
    try:
        response = requests.post(
            f"{BLOOMCHECK_ENDPOINT}/check/raw",
            data=values,
        )
    except requests.ConnectionError as e:
        raise HTTPException(
            status_code=503,
            detail=f"Error connecting to bloomcheck: {e}",
        )
    if response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Error fetching bloomcheck: {response.text}",
        )

    data = response.json()
    if not data:
        return []
    return [BloomHit(**hit) for hit in data]
