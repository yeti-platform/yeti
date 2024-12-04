import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from core.schemas.audit import TimelineLog

router = APIRouter()


@router.get("/timeline/{id:path}")
def trail(id: str):
    return TimelineLog.filter({"target_id": id})
