import asyncio
import json
from typing import Any, Dict, List

import httpx
import websockets
from fastapi import (
    APIRouter,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from core.config.config import yeti_config
from core.schemas import roles
from core.schemas.rbac import global_permission

router = APIRouter()

# Configuration
AGENT_HTTP_BASE = yeti_config.get("agents", "http_root")
AGENT_WEBSOCKET_BASE = yeti_config.get("agents", "websocket_root")

AGENT_STREAM_ENDPOINT = f"{AGENT_HTTP_BASE}/run_stream"
AGENT_LIST_SESSIONS_ENDPOINT = f"{AGENT_HTTP_BASE}/sessions/{{user_id}}"
AGENT_WEBSOCKET_ENDPOINT = f"{AGENT_WEBSOCKET_BASE}/ws/chat"

TIMEOUT = httpx.Timeout(timeout=60.0)


class ADKSession(BaseModel):
    id: str
    appName: str
    userId: str
    state: Dict[str, Any] = Field(default_factory=dict)
    events: List[Dict[str, Any]] = Field(default_factory=list)
    lastUpdateTime: float = 0.0


@router.get("/sessions")
@global_permission(roles.Permission.READ)
def list_sessions_proxy(httpreq: Request) -> List[ADKSession]:
    """
    Proxies the request to retrieve sessions for a given user from the Agent Service.
    """
    user_id = httpreq.state.username
    agent_url = f"{AGENT_LIST_SESSIONS_ENDPOINT.format(user_id=user_id)}"
    with httpx.Client(timeout=TIMEOUT) as client:
        response = client.get(agent_url)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)

        items = response.json()
        return [ADKSession(**item) for item in items]


@router.post("/stream")
@global_permission(roles.Permission.READ)
def chat_proxy(httpreq: Request, message: dict):
    """Proxies a chat message to the Agent Service and streams the response back to the client."""

    username = httpreq.state.username
    agent_payload = {
        "user_id": username,
        "session_id": message.get("session_id"),
        "text": message.get("text"),
    }

    async def proxy_stream():
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            async with client.stream(
                "POST", AGENT_STREAM_ENDPOINT, json=agent_payload
            ) as r:
                async for chunk in r.aiter_bytes():
                    yield chunk

    return StreamingResponse(proxy_stream(), media_type="text/event-stream")
