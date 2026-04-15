"""
Phase 2 — Real-Time Collaboration Service (port 8006).

Provides:
- WebSocket rooms per scan/workspace with presence tracking.
- Team chat with threading and @mention parsing (persisted to PostgreSQL).
- Shared scan-state broadcasts.
- Async REST endpoints for history, presence, and activity feed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from services.common.db import get_db
from services.common.models import CollabMessageModel, CollabReportSectionModel

app = FastAPI(
    title="CosmicSec Collaboration Service",
    description="Phase 2 — Real-time team collaboration, shared workspaces, and live scan feed",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-memory state for WebSocket connections only (not persisted)
# ---------------------------------------------------------------------------


class _Room:
    """WebSocket room with presence and broadcast."""

    def __init__(self, room_id: str):
        self.room_id = room_id
        self.created_at = datetime.now(UTC).isoformat()
        self.connections: dict[str, WebSocket] = {}
        self.scan_state: dict[str, Any] | None = None

    def add_connection(self, username: str, ws: WebSocket) -> None:
        self.connections[username] = ws

    def remove_connection(self, username: str) -> None:
        self.connections.pop(username, None)

    @property
    def present_users(self) -> list[str]:
        return list(self.connections.keys())

    async def broadcast(self, event: dict[str, Any], exclude: str | None = None) -> None:
        dead: list[str] = []
        for user, ws in self.connections.items():
            if user == exclude:
                continue
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(user)
        for u in dead:
            self.connections.pop(u, None)


_rooms: dict[str, _Room] = {}


def _get_or_create_room(room_id: str) -> _Room:
    if room_id not in _rooms:
        _rooms[room_id] = _Room(room_id)
    return _rooms[room_id]


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class SendMessageRequest(BaseModel):
    username: str = Field(..., description="Sender username")
    text: str = Field(..., description="Message text (supports @mention)")
    thread_id: str | None = Field(default=None, description="Thread ID for replies")


class ScanStateUpdate(BaseModel):
    status: str = Field(..., description="Scan status (pending|running|done|failed)")
    progress: int = Field(default=0, ge=0, le=100)
    findings_count: int = Field(default=0)
    updated_by: str = Field(..., description="Username who triggered the update")


class ReportSection(BaseModel):
    section_id: str | None = Field(default=None)
    title: str = Field(..., description="Section heading")
    content: str = Field(..., description="Markdown content for this section")
    author: str = Field(..., description="Username of the author")
    section_type: str = Field(
        default="finding",
        description="executive_summary | finding | recommendation | appendix",
    )


class ReportSectionUpdate(BaseModel):
    title: str | None = Field(default=None)
    content: str | None = Field(default=None)
    editor: str = Field(..., description="Username making this edit")


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------


@app.websocket("/ws/{room_id}")
async def room_websocket(websocket: WebSocket, room_id: str):
    """
    Join a collaboration room over WebSocket.

    Query params:
        username — required, identifies the connecting user.

    Events emitted as JSON:
        {type: "presence",    room, present_users}
        {type: "message",     room, message_id, username, text, ts, thread_id, mentions}
        {type: "scan_update", room, state, updated_by, ts}
        {type: "user_left",   room, username, present_users}
    """
    username: str = websocket.query_params.get("username", f"user_{uuid.uuid4().hex[:6]}")
    await websocket.accept()
    room = _get_or_create_room(room_id)
    room.add_connection(username, websocket)

    await room.broadcast(
        {
            "type": "presence",
            "room": room_id,
            "username": username,
            "event": "joined",
            "present_users": room.present_users,
            "ts": datetime.now(UTC).isoformat(),
        }
    )

    try:
        while True:
            data = await websocket.receive_json()
            ev_type = data.get("type", "message")

            if ev_type == "message":
                text = str(data.get("text", ""))
                mentions = [w[1:] for w in text.split() if w.startswith("@")]
                msg: dict[str, Any] = {
                    "type": "message",
                    "room": room_id,
                    "message_id": uuid.uuid4().hex,
                    "username": username,
                    "text": text,
                    "mentions": mentions,
                    "thread_id": data.get("thread_id"),
                    "ts": datetime.now(UTC).isoformat(),
                }
                await room.broadcast(msg)

            elif ev_type == "scan_update":
                state = {
                    "status": data.get("status", "unknown"),
                    "progress": data.get("progress", 0),
                    "findings_count": data.get("findings_count", 0),
                }
                room.scan_state = state
                await room.broadcast(
                    {
                        "type": "scan_update",
                        "room": room_id,
                        "state": state,
                        "updated_by": username,
                        "ts": datetime.now(UTC).isoformat(),
                    }
                )

            elif ev_type == "ping":
                await websocket.send_json(
                    {"type": "pong", "ts": datetime.now(UTC).isoformat()}
                )

    except WebSocketDisconnect:
        room.remove_connection(username)
        await room.broadcast(
            {
                "type": "user_left",
                "room": room_id,
                "username": username,
                "present_users": room.present_users,
                "ts": datetime.now(UTC).isoformat(),
            }
        )


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health_check() -> dict:
    return {
        "status": "healthy",
        "service": "collab",
        "active_rooms": len(_rooms),
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/rooms")
async def list_rooms() -> dict:
    return {
        "rooms": [
            {
                "room_id": rid,
                "present_users": r.present_users,
                "created_at": r.created_at,
            }
            for rid, r in _rooms.items()
        ]
    }


@app.get("/rooms/{room_id}/messages")
async def get_messages(room_id: str, limit: int = 50, db: Session = Depends(get_db)) -> dict:
    messages = (
        db.query(CollabMessageModel)
        .filter(CollabMessageModel.room_id == room_id)
        .order_by(CollabMessageModel.created_at.desc())
        .limit(limit)
        .all()
    )
    result = [_msg_to_dict(m) for m in reversed(messages)]
    return {"room_id": room_id, "messages": result, "total": len(result)}


@app.get("/rooms/{room_id}/presence")
async def get_presence(room_id: str) -> dict:
    room = _get_or_create_room(room_id)
    return {
        "room_id": room_id,
        "present_users": room.present_users,
        "count": len(room.present_users),
    }


@app.get("/rooms/{room_id}/scan-state")
async def get_scan_state(room_id: str) -> dict:
    room = _get_or_create_room(room_id)
    return {"room_id": room_id, "scan_state": room.scan_state}


@app.post("/rooms/{room_id}/messages")
async def post_message(
    room_id: str, payload: SendMessageRequest, db: Session = Depends(get_db)
) -> dict:
    """POST a message into a room (for non-WebSocket clients). Persisted to DB."""
    mentions = [w[1:] for w in payload.text.split() if w.startswith("@")]
    message_id = uuid.uuid4().hex
    msg_row = CollabMessageModel(
        id=message_id,
        room_id=room_id,
        username=payload.username,
        text=payload.text,
        mentions=mentions,
        thread_id=payload.thread_id,
    )
    db.add(msg_row)
    db.commit()
    msg: dict[str, Any] = {
        "type": "message",
        "room": room_id,
        "message_id": message_id,
        "username": payload.username,
        "text": payload.text,
        "mentions": mentions,
        "thread_id": payload.thread_id,
        "ts": msg_row.created_at.isoformat()
        if msg_row.created_at
        else datetime.now(UTC).isoformat(),
    }
    room = _get_or_create_room(room_id)
    await room.broadcast(msg)
    return {"status": "sent", "message_id": message_id}


@app.post("/rooms/{room_id}/scan-state")
async def update_scan_state(room_id: str, payload: ScanStateUpdate) -> dict:
    room = _get_or_create_room(room_id)
    state = {
        "status": payload.status,
        "progress": payload.progress,
        "findings_count": payload.findings_count,
    }
    room.scan_state = state
    await room.broadcast(
        {
            "type": "scan_update",
            "room": room_id,
            "state": state,
            "updated_by": payload.updated_by,
            "ts": datetime.now(UTC).isoformat(),
        }
    )
    return {"room_id": room_id, "state": state}


@app.get("/activity-feed")
async def activity_feed(limit: int = 20, db: Session = Depends(get_db)) -> dict:
    """Global activity feed — latest messages across all rooms."""
    messages = (
        db.query(CollabMessageModel)
        .order_by(CollabMessageModel.created_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "feed": [_msg_to_dict(m) for m in messages],
        "total_events": len(messages),
    }


# ==========================================================================
# Phase 2 — Collaborative Report Editing (persisted to DB)
# ==========================================================================


@app.post("/rooms/{room_id}/reports", status_code=201)
async def create_report_section(
    room_id: str, payload: ReportSection, db: Session = Depends(get_db)
) -> dict:
    section_id = payload.section_id or uuid.uuid4().hex
    section_row = CollabReportSectionModel(
        id=section_id,
        room_id=room_id,
        title=payload.title,
        content=payload.content,
        author=payload.author,
        section_type=payload.section_type,
        revision=1,
        edit_history=[],
    )
    db.add(section_row)
    db.commit()
    db.refresh(section_row)

    now = (
        section_row.created_at.isoformat()
        if section_row.created_at
        else datetime.now(UTC).isoformat()
    )
    room = _get_or_create_room(room_id)
    await room.broadcast(
        {
            "type": "report_update",
            "action": "created",
            "room": room_id,
            "section_id": section_id,
            "title": payload.title,
            "author": payload.author,
            "ts": now,
        }
    )
    return _section_to_dict(section_row)


@app.get("/rooms/{room_id}/reports")
async def list_report_sections(
    room_id: str, section_type: str | None = None, db: Session = Depends(get_db)
) -> dict:
    query = db.query(CollabReportSectionModel).filter(CollabReportSectionModel.room_id == room_id)
    if section_type:
        query = query.filter(CollabReportSectionModel.section_type == section_type)
    sections = query.order_by(CollabReportSectionModel.created_at).all()
    return {
        "room_id": room_id,
        "sections": [_section_to_dict(s) for s in sections],
        "total": len(sections),
    }


@app.get("/rooms/{room_id}/reports/{section_id}")
async def get_report_section(room_id: str, section_id: str, db: Session = Depends(get_db)) -> dict:
    section = (
        db.query(CollabReportSectionModel)
        .filter(
            CollabReportSectionModel.id == section_id,
            CollabReportSectionModel.room_id == room_id,
        )
        .first()
    )
    if section is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Section not found")
    return _section_to_dict(section)


@app.put("/rooms/{room_id}/reports/{section_id}")
async def update_report_section(
    room_id: str, section_id: str, payload: ReportSectionUpdate, db: Session = Depends(get_db)
) -> dict:
    from fastapi import HTTPException

    section = (
        db.query(CollabReportSectionModel)
        .filter(
            CollabReportSectionModel.id == section_id,
            CollabReportSectionModel.room_id == room_id,
        )
        .first()
    )
    if section is None:
        raise HTTPException(status_code=404, detail="Section not found")

    now = datetime.now(UTC).isoformat()
    history = list(section.edit_history or [])
    history.append(
        {
            "revision": section.revision,
            "title": section.title,
            "content": section.content,
            "updated_at": section.updated_at.isoformat() if section.updated_at else now,
            "editor": payload.editor,
        }
    )
    section.edit_history = history[-20:]
    if payload.title is not None:
        section.title = payload.title
    if payload.content is not None:
        section.content = payload.content
    section.revision += 1
    db.commit()
    db.refresh(section)

    room = _get_or_create_room(room_id)
    await room.broadcast(
        {
            "type": "report_update",
            "action": "edited",
            "room": room_id,
            "section_id": section_id,
            "title": section.title,
            "editor": payload.editor,
            "revision": section.revision,
            "ts": section.updated_at.isoformat() if section.updated_at else now,
        }
    )
    return _section_to_dict(section)


@app.delete("/rooms/{room_id}/reports/{section_id}")
async def delete_report_section(
    room_id: str, section_id: str, editor: str = "api", db: Session = Depends(get_db)
) -> dict:
    from fastapi import HTTPException

    section = (
        db.query(CollabReportSectionModel)
        .filter(
            CollabReportSectionModel.id == section_id,
            CollabReportSectionModel.room_id == room_id,
        )
        .first()
    )
    if section is None:
        raise HTTPException(status_code=404, detail="Section not found")
    db.delete(section)
    db.commit()

    room = _get_or_create_room(room_id)
    await room.broadcast(
        {
            "type": "report_update",
            "action": "deleted",
            "room": room_id,
            "section_id": section_id,
            "editor": editor,
            "ts": datetime.now(UTC).isoformat(),
        }
    )
    return {"status": "deleted", "section_id": section_id}


@app.get("/rooms/{room_id}/reports/{section_id}/history")
async def get_section_history(room_id: str, section_id: str, db: Session = Depends(get_db)) -> dict:
    from fastapi import HTTPException

    section = (
        db.query(CollabReportSectionModel)
        .filter(
            CollabReportSectionModel.id == section_id,
            CollabReportSectionModel.room_id == room_id,
        )
        .first()
    )
    if section is None:
        raise HTTPException(status_code=404, detail="Section not found")
    return {
        "section_id": section_id,
        "current_revision": section.revision,
        "history": section.edit_history,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _msg_to_dict(m: CollabMessageModel) -> dict:
    return {
        "type": "message",
        "room": m.room_id,
        "message_id": m.id,
        "username": m.username,
        "text": m.text,
        "mentions": m.mentions,
        "thread_id": m.thread_id,
        "ts": m.created_at.isoformat() if m.created_at else None,
    }


def _section_to_dict(s: CollabReportSectionModel) -> dict:
    return {
        "section_id": s.id,
        "room_id": s.room_id,
        "title": s.title,
        "content": s.content,
        "author": s.author,
        "section_type": s.section_type,
        "created_at": s.created_at.isoformat() if s.created_at else None,
        "updated_at": s.updated_at.isoformat() if s.updated_at else None,
        "revision": s.revision,
        "edit_history": s.edit_history,
    }
