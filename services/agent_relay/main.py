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
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
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


def _persist_agent_session(
    *,
    agent_id: str,
    user_id: str | None,
    status: str,
    last_seen_ts: float,
    manifest: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> None:
    """Persist session state to DB when a validated user identity is available."""
    if not user_id:
        return

    try:
        from services.common.db import SessionLocal
        from services.common.models import AgentSessionModel

        db = SessionLocal()
        try:
            existing = db.query(AgentSessionModel).filter(AgentSessionModel.id == agent_id).first()
            timestamp = datetime.fromtimestamp(last_seen_ts, tz=UTC)
            if existing:
                existing.user_id = user_id
                existing.status = status
                existing.last_seen_at = timestamp
                if manifest is not None:
                    existing.manifest = manifest
                if ip_address is not None:
                    existing.ip_address = ip_address
            else:
                db.add(
                    AgentSessionModel(
                        id=agent_id,
                        user_id=user_id,
                        manifest=manifest or {},
                        status=status,
                        last_seen_at=timestamp,
                        ip_address=ip_address,
                    )
                )
            db.commit()
        finally:
            db.close()
    except Exception:
        logger.debug("DB upsert for agent %s failed (non-critical)", agent_id, exc_info=True)


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


@app.get("/relay/agents/history")
async def list_agent_history(
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> JSONResponse:
    """Return durable agent session history from DB with optional status filter."""
    try:
        from services.common.db import SessionLocal
        from services.common.models import AgentSessionModel

        db = SessionLocal()
        try:
            base_query = db.query(AgentSessionModel)
            if status_filter:
                base_query = base_query.filter(AgentSessionModel.status == status_filter)

            total = base_query.count()
            rows = (
                base_query.order_by(AgentSessionModel.last_seen_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )

            items = [
                {
                    "agent_id": row.id,
                    "user_id": row.user_id,
                    "status": row.status,
                    "manifest": row.manifest or {},
                    "ip_address": row.ip_address,
                    "last_seen_at": (
                        row.last_seen_at.isoformat() if getattr(row, "last_seen_at", None) else None
                    ),
                    "created_at": (
                        row.created_at.isoformat() if getattr(row, "created_at", None) else None
                    ),
                }
                for row in rows
            ]
            return JSONResponse(
                content={
                    "items": items,
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                    "source": "database",
                }
            )
        finally:
            db.close()
    except Exception:
        logger.warning("Agent session history unavailable from DB", exc_info=True)
        return JSONResponse(
            status_code=503,
            content={
                "items": [],
                "total": 0,
                "limit": limit,
                "offset": offset,
                "source": "unavailable",
            },
        )


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
    authenticated_user_id: str | None = None

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
                    authenticated_user_id = row.user_id
            finally:
                db.close()
        except Exception:
            logger.warning("DB-based API key validation unavailable", exc_info=True)

    # Try JWT token authentication
    if token and not authenticated:
        claims = decode_token(token)
        if claims is not None:
            authenticated = True
            claim_user_id = claims.get("user_id")
            if isinstance(claim_user_id, str) and claim_user_id.strip():
                authenticated_user_id = claim_user_id.strip()
            elif isinstance(claims.get("sub"), str) and claims.get("sub", "").strip():
                # Fallback: resolve user id from email subject claim.
                subject_email = claims.get("sub", "").strip()
                try:
                    from services.common.db import SessionLocal
                    from services.common.models import UserModel

                    db = SessionLocal()
                    try:
                        user = db.query(UserModel).filter(UserModel.email == subject_email).first()
                        if user and isinstance(user.id, str):
                            authenticated_user_id = user.id
                    finally:
                        db.close()
                except Exception:
                    logger.debug("Failed resolving user_id from JWT sub", exc_info=True)

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
        "user_id": authenticated_user_id,
    }
    logger.info("Agent %s connected via relay", safe_agent_id)

    # Persist connection lifecycle in DB when user identity is known.
    _persist_agent_session(
        agent_id=agent_id,
        user_id=authenticated_user_id,
        status="connected",
        last_seen_ts=now,
        manifest={},
        ip_address=websocket.client.host if websocket.client else None,
    )

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
                manifest_payload = msg.get("payload", {})
                if isinstance(manifest_payload, dict):
                    _connections[agent_id]["manifest"] = manifest_payload
                logger.info("Agent %s registered manifest", safe_agent_id)
                _persist_agent_session(
                    agent_id=agent_id,
                    user_id=authenticated_user_id,
                    status="connected",
                    last_seen_ts=_connections[agent_id]["last_seen_at"],
                    manifest=_connections[agent_id]["manifest"],
                )
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
        _persist_agent_session(
            agent_id=agent_id,
            user_id=authenticated_user_id,
            status="disconnected",
            last_seen_ts=time.time(),
            manifest={},
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
