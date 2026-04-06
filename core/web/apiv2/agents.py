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

ASYNC_TIMEOUT = httpx.Timeout(timeout=60.0)

class ADKSession(BaseModel):
    id: str
    appName: str
    userId: str
    state: Dict[str, Any] = Field(default_factory=dict)
    events: List[Dict[str, Any]] = Field(default_factory=list)
    lastUpdateTime: float = 0.0

@router.get("/sessions")
@global_permission(roles.Permission.READ)
async def list_sessions_proxy(httpreq: Request) -> List[ADKSession]:
    """
    Proxies the request to retrieve sessions for a given user from the Agent Service.
    """
    user_id = httpreq.state.username
    agent_url = f"{AGENT_LIST_SESSIONS_ENDPOINT.format(user_id=user_id)}"
    async with httpx.AsyncClient(timeout=ASYNC_TIMEOUT) as client:
        response = await client.get(agent_url)
        print(response)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)

        # Parse the JSON response from the agent service into our Pydantic model
        # which validates it matches the expected schema
        items = response.json()
        print(items)
        return [ADKSession(**item) for item in items]

@router.post("/stream")
@global_permission(roles.Permission.READ)
async def chat_proxy(httpreq: Request, message: dict):
    """
    1. Authenticates user.
    2. Fetches relevant context (optional).
    3. Forwards request to Agent Service.
    4. Streams response back to Frontend.
    """

    username = httpreq.state.username

    # # 1. Inject Context (RAG or Database lookup)
    # # E.g., "Alice is an admin looking at dashboard page X"
    # system_context = (
    #     f"User {username} is asking about page {message.get('current_page')}"
    # )

    # 2. Prepare Payload for Agent
    agent_payload = {
        "user_id": username,
        "session_id": message.get("session_id"),
        "text": message.get("text"),
        # "context_override": system_context,  # Custom field your agent knows how to handle
    }

    # 3. Stream the response from the Agent Service
    async def proxy_stream():
        async with httpx.AsyncClient(timeout=ASYNC_TIMEOUT) as client:
            async with client.stream(
                "POST", AGENT_STREAM_ENDPOINT, json=agent_payload
            ) as r:
                async for chunk in r.aiter_bytes():
                    yield chunk

    return StreamingResponse(proxy_stream(), media_type="text/event-stream")
