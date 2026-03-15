import asyncio
import json

import httpx
import websockets
from typing import Any, Dict, List
from fastapi import APIRouter, FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

router = APIRouter()

# Configuration
RUN_STREAM_ENDPOINT = "/run_stream"
LIST_SESSIONS_ENDPOINT = "/sessions/{user_id}"

AGENT_SERVICE_ROOT = "http://dev-agents-1:8888"


ASYNC_TIMEOUT = httpx.Timeout(timeout=60.0)

class ADKSession(BaseModel):
    id: str
    appName: str
    userId: str
    state: Dict[str, Any] = Field(default_factory=dict)
    events: List[Dict[str, Any]] = Field(default_factory=list)
    lastUpdateTime: float = 0.0

@router.get("/sessions/{user_id}")
async def list_sessions_proxy(user_id: str) -> List[ADKSession]:
    """
    Proxies the request to retrieve sessions for a given user from the Agent Service.
    """
    agent_url = f"{AGENT_SERVICE_ROOT}{LIST_SESSIONS_ENDPOINT.format(user_id=user_id)}"

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
                "POST", AGENT_SERVICE_ROOT + RUN_STREAM_ENDPOINT, json=agent_payload
            ) as r:
                async for chunk in r.aiter_bytes():
                    yield chunk

    return StreamingResponse(proxy_stream(), media_type="text/event-stream")


# The internal address of your standalone Agent Service
AGENT_SERVICE_WS_URL = "ws://dev-agents-1:8888/ws/chat"

@router.websocket("/api/v2/chat_proxy")
async def chat_proxy_endpoint(client_ws: WebSocket):
    """
    1. Accepts connection from Vue.js
    2. Authenticates user (via Cookie or Query Param).
    3. Connects to Agent Service.
    4. Injects User ID and forwards messages bi-directionally.
    """

    # --- 1. Handshake & Auth ---
    # In WebSockets, headers are hard to customize on the client.
    # We often read the token from query params: ws://.../proxy?token=xyz
    # token = client_ws.query_params.get("token")
    # user = validate_token(token) # Your custom auth logic

    # if not user:
    #     await client_ws.close(code=1008) # Policy Violation
    #     return

    await client_ws.accept()

    # --- 2. The Tunnel Loop ---
    try:
        # Connect to the Agent Service as a client
        async with websockets.connect(AGENT_SERVICE_WS_URL) as agent_ws:

            # Task A: Listen to Frontend -> Inject ID -> Send to Agent
            async def forward_to_agent():
                try:
                    while True:
                        # Wait for message from Vue
                        data = await client_ws.receive_text()
                        message_payload = json.loads(data)

                        # SECURITY: Overwrite/Inject the verified User ID
                        # This ensures the Agent Service trusts the ID provided by the Proxy
                        message_payload["user_id"] = user["id"]

                        # Forward to Agent Service
                        await agent_ws.send(json.dumps(message_payload))
                except WebSocketDisconnect:
                    # Frontend disconnected
                    pass
                except Exception as e:
                    print(f"Error forwarding to agent: {e}")

            # Task B: Listen to Agent -> Forward to Frontend
            async def forward_to_client():
                try:
                    async for message in agent_ws:
                        # Forward raw message (tokens/JSON) back to Vue
                        await client_ws.send_text(message)
                except Exception as e:
                    print(f"Error forwarding to client: {e}")

            # --- 3. Run both directions concurrently ---
            # If either side disconnects, the gather will eventually exit/cancel
            await asyncio.gather(
                forward_to_agent(),
                forward_to_client(),
                return_exceptions=True
            )

    except Exception as e:
        print(f"Proxy Connection Error: {e}")
        # Ensure client socket is closed if upstream fails
        try:
            await client_ws.close()
        except:
            pass
