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
AGENT_MODELS_ENDPOINT = f"{AGENT_HTTP_BASE}/models"
AGENT_GET_SESSION_ENDPOINT = f"{AGENT_HTTP_BASE}/sessions/{{user_id}}/{{session_id}}"
AGENT_WEBSOCKET_ENDPOINT = f"{AGENT_WEBSOCKET_BASE}/ws/chat"

TIMEOUT = httpx.Timeout(timeout=60.0)


class ADKSession(BaseModel):
    # Every field the agent service reports has to be declared here or it is
    # dropped on the way out, silently: the UI reads what this model keeps, not
    # what the agent service sent.
    id: str
    appName: str
    userId: str
    state: Dict[str, Any] = Field(default_factory=dict)
    events: List[Dict[str, Any]] = Field(default_factory=list)
    lastUpdateTime: float = 0.0
    createTime: float | None = None
    title: str | None = None
    model: str | None = None
    persona: str | None = None


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


@router.get("/sessions/{session_id}")
@global_permission(roles.Permission.READ)
def get_session_proxy(httpreq: Request, session_id: str) -> ADKSession:
    """
    Proxies the request to retrieve a single session for a given user from the Agent Service.
    """
    user_id = httpreq.state.username
    agent_url = (
        f"{AGENT_GET_SESSION_ENDPOINT.format(user_id=user_id, session_id=session_id)}"
    )
    with httpx.Client(timeout=TIMEOUT) as client:
        response = client.get(agent_url)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)

        return ADKSession(**response.json())


class ModelsResponse(BaseModel):
    """The models the agent service will accept for a chat request."""

    provider: str
    models: List[str]
    default: str


@router.get("/models")
@global_permission(roles.Permission.READ)
def list_models_proxy(httpreq: Request) -> ModelsResponse:
    """Proxies the list of models the Agent Service is configured to offer."""
    with httpx.Client(timeout=TIMEOUT) as client:
        response = client.get(AGENT_MODELS_ENDPOINT)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail=response.text)
        return ModelsResponse(**response.json())


@router.delete("/sessions/{session_id}", status_code=204)
@global_permission(roles.Permission.READ)
def delete_session_proxy(httpreq: Request, session_id: str) -> None:
    """Deletes one of the calling user's chat sessions.

    The user id comes from the request rather than the caller, as it does for
    reads, so a session can only be deleted by the user it belongs to.
    """
    user_id = httpreq.state.username
    agent_url = AGENT_GET_SESSION_ENDPOINT.format(
        user_id=user_id, session_id=session_id
    )
    with httpx.Client(timeout=TIMEOUT) as client:
        response = client.delete(agent_url)
        if response.status_code not in (204, 200):
            raise HTTPException(status_code=response.status_code, detail=response.text)


@router.post("/stream")
@global_permission(roles.Permission.READ)
def chat_proxy(httpreq: Request, message: dict):
    """Proxies a chat message to the Agent Service and streams the response back to the client."""

    username = httpreq.state.username
    # An allowlist rather than a passthrough: user_id is taken from the
    # authenticated request, so forwarding the body wholesale would let a caller
    # set it themselves and read another user's session.
    agent_payload = {
        "user_id": username,
        "session_id": message.get("session_id"),
        "text": message.get("text"),
        "model": message.get("model"),
        "persona": message.get("persona"),
    }

    async def proxy_stream():
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            async with client.stream(
                "POST", AGENT_STREAM_ENDPOINT, json=agent_payload
            ) as r:
                async for chunk in r.aiter_bytes():
                    yield chunk

    return StreamingResponse(proxy_stream(), media_type="text/event-stream")
