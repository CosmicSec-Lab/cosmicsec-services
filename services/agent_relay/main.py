"""
CosmicSec Agent Relay Service
Lightweight FastAPI service (port 8011) that manages agent WebSocket connections
and dispatches tasks to connected agents.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="CosmicSec Agent Relay",
    description="Manages CLI agent WebSocket connections and task dispatching",
    version="0.1.0",
)

# ---------------------------------------------------------------------------
# CORS — explicit origins; no wildcard when credentials are used
# ---------------------------------------------------------------------------
_ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get(
        "ALLOWED_ORIGINS",
        "http://localhost:3000,http://localhost:8000",
    ).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-memory connection registry (non-persistent by design)
# ---------------------------------------------------------------------------

# agent_id → { websocket, connected_at, last_seen_at, manifest }
_connections: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Internal relay key — shared secret for service-to-service dispatch calls
# ---------------------------------------------------------------------------
_RELAY_SECRET = os.environ.get("RELAY_INTERNAL_SECRET", "")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class DispatchTaskRequest(BaseModel):
    """Payload for dispatching a task to a specific agent."""

    agent_id: str
    task: dict


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict:
    """Health check."""
    return {"status": "healthy", "service": "agent-relay", "timestamp": time.time()}


@app.get("/relay/agents")
async def list_agents() -> JSONResponse:
    """Return all currently connected agents with their last-seen timestamps."""
    agents = [
        {
            "agent_id": aid,
            "connected_at": meta["connected_at"],
            "last_seen_at": meta["last_seen_at"],
            "manifest": meta.get("manifest", {}),
        }
        for aid, meta in _connections.items()
    ]
    return JSONResponse(content={"agents": agents, "total": len(agents)})


@app.post("/relay/dispatch-task")
async def dispatch_task(payload: DispatchTaskRequest, request: Request) -> JSONResponse:
    """Send a task message to a specific connected agent.

    Protected by ``X-Relay-Secret`` header (must match ``RELAY_INTERNAL_SECRET``
    environment variable).  Returns 404 if the agent is not currently connected.
    """
    # Service-to-service auth via shared secret
    if _RELAY_SECRET:
        provided = request.headers.get("X-Relay-Secret", "")
        if not provided or provided != _RELAY_SECRET:
            raise HTTPException(status_code=403, detail="Forbidden")

    agent_id = payload.agent_id
    if agent_id not in _connections:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id!r} is not connected")

    ws: WebSocket = _connections[agent_id]["websocket"]
    try:
        await ws.send_json({"type": "task", "payload": payload.task})
    except Exception:
        logger.exception("Failed to dispatch task to agent %s", agent_id)
        raise HTTPException(status_code=503, detail="Failed to deliver task to agent")

    return JSONResponse(content={"dispatched": True, "agent_id": agent_id})


@app.websocket("/ws/relay/agent/{agent_id}")
async def agent_ws(websocket: WebSocket, agent_id: str) -> None:
    """Primary WebSocket endpoint for CLI agent connections.

    Authenticates via ``api_key`` query parameter (validated non-empty).
    Receives JSON messages from the agent and updates last-seen timestamps.
    """
    api_key = websocket.query_params.get("api_key") or websocket.headers.get("x-api-key")
    if not api_key:
        await websocket.close(code=4001)
        return

    await websocket.accept()

    now = time.time()
    _connections[agent_id] = {
        "websocket": websocket,
        "connected_at": now,
        "last_seen_at": now,
        "manifest": {},
    }
    logger.info("Agent %s connected via relay", agent_id)

    heartbeat_task = asyncio.create_task(_heartbeat(websocket, agent_id))

    try:
        while True:
            raw = await websocket.receive_text()
            _connections[agent_id]["last_seen_at"] = time.time()

            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning("Agent %s sent non-JSON data", agent_id)
                continue

            msg_type = msg.get("type", "")

            if msg_type == "manifest":
                _connections[agent_id]["manifest"] = msg.get("payload", {})
                logger.info("Agent %s registered manifest", agent_id)
            elif msg_type == "finding":
                logger.info(
                    "Agent %s submitted finding: %s",
                    agent_id,
                    msg.get("payload", {}).get("title", "(no title)"),
                )
            elif msg_type == "scan_complete":
                logger.info("Agent %s scan complete: %s", agent_id, msg.get("scan_id"))
            else:
                logger.debug("Agent %s unknown message type: %s", agent_id, msg_type)

    except WebSocketDisconnect:
        logger.info("Agent %s disconnected from relay", agent_id)
    finally:
        heartbeat_task.cancel()
        _connections.pop(agent_id, None)


async def _heartbeat(websocket: WebSocket, agent_id: str) -> None:
    """Ping the agent every 30 seconds to keep the connection alive."""
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_json({"type": "heartbeat", "ts": time.time()})
    except Exception:
        pass


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8011)
