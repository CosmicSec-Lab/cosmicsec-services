"""
CosmicSec Agent Relay Service
Lightweight FastAPI service (port 8011) that manages agent WebSocket connections
and dispatches tasks to connected agents.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from services.common.jwt_utils import decode_token
from services.common.security_utils import sanitize_for_log

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
_API_KEY_HASH_SECRET = os.environ.get("API_KEY_HASH_SECRET", _RELAY_SECRET or "cosmicsec-api-key")


def _hash_api_key_token(token: str) -> str:
    return hmac.new(
        _API_KEY_HASH_SECRET.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


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
    safe_agent_id = sanitize_for_log(agent_id)
    if agent_id not in _connections:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id!r} is not connected")

    ws: WebSocket = _connections[agent_id]["websocket"]
    try:
        await ws.send_json({"type": "task", "payload": payload.task})
    except (WebSocketDisconnect, RuntimeError, OSError):
        logger.exception("Failed to dispatch task to agent %s", safe_agent_id)
        raise HTTPException(status_code=503, detail="Failed to deliver task to agent")

    return JSONResponse(content={"dispatched": True, "agent_id": agent_id})


@app.websocket("/ws/relay/agent/{agent_id}")
async def agent_ws(websocket: WebSocket, agent_id: str) -> None:
    """Primary WebSocket endpoint for CLI agent connections.

    Authenticates via ``api_key`` query parameter (validated against the DB)
    or via a JWT ``token`` query parameter.  If neither is valid the
    connection is rejected with close code 4001.
    """
    safe_agent_id = sanitize_for_log(agent_id)
    api_key = websocket.query_params.get("api_key") or websocket.headers.get("x-api-key")
    token = websocket.query_params.get("token")
    if not token:
        auth_header = websocket.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:].strip()

    authenticated = False

    # Try API key authentication — validate against the database
    if api_key and not authenticated:
        try:
            from sqlalchemy.orm import Session as _SASession

            from services.common.db import SessionLocal
            from services.common.models import APIKeyModel

            candidate_hash = _hash_api_key_token(api_key)
            db: _SASession = SessionLocal()
            try:
                row = (
                    db.query(APIKeyModel)
                    .filter(APIKeyModel.key_hash == candidate_hash, APIKeyModel.is_active.is_(True))
                    .first()
                )
                if row is not None and hmac.compare_digest(row.key_hash or "", candidate_hash):
                    authenticated = True
            finally:
                db.close()
        except Exception:
            logger.warning("DB-based API key validation unavailable", exc_info=True)

    # Try JWT token authentication
    if token and not authenticated:
        claims = decode_token(token)
        if claims is not None:
            authenticated = True

    if not authenticated:
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
    logger.info("Agent %s connected via relay", safe_agent_id)

    # Persist agent session to database (upsert)
    try:
        from services.common.db import SessionLocal
        from services.common.models import AgentSessionModel

        db = SessionLocal()
        existing = db.query(AgentSessionModel).filter(AgentSessionModel.id == agent_id).first()
        if existing:
            existing.status = "connected"
            existing.last_seen_at = datetime.fromtimestamp(now, tz=UTC)
        else:
            session = AgentSessionModel(
                id=agent_id,
                user_id=agent_id,  # fallback — real user_id from JWT when available
                manifest={},
                status="connected",
                last_seen_at=datetime.fromtimestamp(now, tz=UTC),
            )
            db.add(session)
        db.commit()
        db.close()
    except Exception:
        logger.debug("DB upsert for agent %s failed (non-critical)", safe_agent_id, exc_info=True)

    heartbeat_task = asyncio.create_task(_heartbeat(websocket, agent_id))

    try:
        while True:
            raw = await websocket.receive_text()
            _connections[agent_id]["last_seen_at"] = time.time()

            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning("Agent %s sent non-JSON data", safe_agent_id)
                await websocket.send_json({"type": "error", "detail": "Invalid JSON payload"})
                continue

            if not isinstance(msg, dict) or "type" not in msg:
                logger.warning("Agent %s sent message without 'type' field", safe_agent_id)
                await websocket.send_json(
                    {"type": "error", "detail": "Message must be a JSON object with a 'type' field"}
                )
                continue

            msg_type = msg.get("type", "")

            if msg_type == "manifest":
                _connections[agent_id]["manifest"] = msg.get("payload", {})
                logger.info("Agent %s registered manifest", safe_agent_id)
            elif msg_type == "finding":
                logger.info(
                    "Agent %s submitted finding: %s",
                    safe_agent_id,
                    sanitize_for_log(msg.get("payload", {}).get("title", "(no title)")),
                )
            elif msg_type == "scan_complete":
                logger.info(
                    "Agent %s scan complete: %s",
                    safe_agent_id,
                    sanitize_for_log(msg.get("scan_id")),
                )
            else:
                logger.debug(
                    "Agent %s unknown message type: %s", safe_agent_id, sanitize_for_log(msg_type)
                )

    except WebSocketDisconnect:
        logger.info("Agent %s disconnected from relay", safe_agent_id)
    finally:
        heartbeat_task.cancel()
        _connections.pop(agent_id, None)
        # Persist disconnection to database
        try:
            from services.common.db import SessionLocal
            from services.common.models import AgentSessionModel

            db = SessionLocal()
            row = db.query(AgentSessionModel).filter(AgentSessionModel.id == agent_id).first()
            if row:
                row.status = "disconnected"
            db.commit()
            db.close()
        except Exception:
            logger.debug(
                "DB status update for agent %s disconnect failed", safe_agent_id, exc_info=True
            )


async def _heartbeat(websocket: WebSocket, agent_id: str) -> None:
    """Ping the agent every 30 seconds to keep the connection alive."""
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_json({"type": "heartbeat", "ts": time.time()})
    except Exception:
        logger.debug("Heartbeat loop ended for agent %s", sanitize_for_log(agent_id), exc_info=True)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.getenv("COSMICSEC_BIND_HOST", "127.0.0.1"), port=8011)
