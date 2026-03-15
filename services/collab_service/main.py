"""
Phase 2 — Real-Time Collaboration Service (port 8006).

Provides:
- WebSocket rooms per scan/workspace with presence tracking.
- Team chat with threading and @mention parsing.
- Shared scan-state broadcasts.
- Async REST endpoints for history, presence, and activity feed.
"""
from __future__ import annotations

import asyncio
import uuid
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

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
# In-memory state (replace with Redis pub/sub for production multi-replica)
# ---------------------------------------------------------------------------

class _Room:
    """WebSocket room with presence, message history, and broadcast."""

    def __init__(self, room_id: str):
        self.room_id = room_id
        self.created_at = datetime.utcnow().isoformat()
        self.connections: Dict[str, WebSocket] = {}  # username → ws
        self.messages: List[Dict[str, Any]] = []
        self.scan_state: Optional[Dict[str, Any]] = None

    def add_connection(self, username: str, ws: WebSocket) -> None:
        self.connections[username] = ws

    def remove_connection(self, username: str) -> None:
        self.connections.pop(username, None)

    @property
    def present_users(self) -> List[str]:
        return list(self.connections.keys())

    async def broadcast(self, event: Dict[str, Any], exclude: Optional[str] = None) -> None:
        dead: List[str] = []
        for user, ws in self.connections.items():
            if user == exclude:
                continue
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(user)
        for u in dead:
            self.connections.pop(u, None)

    def add_message(self, msg: Dict[str, Any]) -> None:
        self.messages.append(msg)
        # Keep last 500 messages in memory
        if len(self.messages) > 500:
            self.messages = self.messages[-500:]


_rooms: Dict[str, _Room] = {}


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
    thread_id: Optional[str] = Field(default=None, description="Thread ID for replies")


class ScanStateUpdate(BaseModel):
    status: str = Field(..., description="Scan status (pending|running|done|failed)")
    progress: int = Field(default=0, ge=0, le=100)
    findings_count: int = Field(default=0)
    updated_by: str = Field(..., description="Username who triggered the update")


    class ReportSection(BaseModel):
        section_id: Optional[str] = Field(default=None)
        title: str = Field(..., description="Section heading")
        content: str = Field(..., description="Markdown content for this section")
        author: str = Field(..., description="Username of the author")
        section_type: str = Field(
            default="finding",
            description="executive_summary | finding | recommendation | appendix",
        )


    class ReportSectionUpdate(BaseModel):
        title: Optional[str] = Field(default=None)
        content: Optional[str] = Field(default=None)
        editor: str = Field(..., description="Username making this edit")


    # Per-room report sections: _report_store[room_id][section_id] = section_dict
    _report_store: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)


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

    # Announce presence
    await room.broadcast({
        "type": "presence",
        "room": room_id,
        "username": username,
        "event": "joined",
        "present_users": room.present_users,
        "ts": datetime.utcnow().isoformat(),
    })

    try:
        while True:
            data = await websocket.receive_json()
            ev_type = data.get("type", "message")

            if ev_type == "message":
                text = str(data.get("text", ""))
                mentions = [w[1:] for w in text.split() if w.startswith("@")]
                msg: Dict[str, Any] = {
                    "type": "message",
                    "room": room_id,
                    "message_id": uuid.uuid4().hex,
                    "username": username,
                    "text": text,
                    "mentions": mentions,
                    "thread_id": data.get("thread_id"),
                    "ts": datetime.utcnow().isoformat(),
                }
                room.add_message(msg)
                await room.broadcast(msg)

            elif ev_type == "scan_update":
                state = {
                    "status": data.get("status", "unknown"),
                    "progress": data.get("progress", 0),
                    "findings_count": data.get("findings_count", 0),
                }
                room.scan_state = state
                await room.broadcast({
                    "type": "scan_update",
                    "room": room_id,
                    "state": state,
                    "updated_by": username,
                    "ts": datetime.utcnow().isoformat(),
                })

            elif ev_type == "ping":
                await websocket.send_json({"type": "pong", "ts": datetime.utcnow().isoformat()})

    except WebSocketDisconnect:
        room.remove_connection(username)
        await room.broadcast({
            "type": "user_left",
            "room": room_id,
            "username": username,
            "present_users": room.present_users,
            "ts": datetime.utcnow().isoformat(),
        })


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health_check() -> dict:
    return {
        "status": "healthy",
        "service": "collab",
        "active_rooms": len(_rooms),
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/rooms")
async def list_rooms() -> dict:
    return {
        "rooms": [
            {
                "room_id": rid,
                "present_users": r.present_users,
                "message_count": len(r.messages),
                "created_at": r.created_at,
            }
            for rid, r in _rooms.items()
        ]
    }


@app.get("/rooms/{room_id}/messages")
async def get_messages(room_id: str, limit: int = 50) -> dict:
    room = _get_or_create_room(room_id)
    return {
        "room_id": room_id,
        "messages": room.messages[-limit:],
        "total": len(room.messages),
    }


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
    return {
        "room_id": room_id,
        "scan_state": room.scan_state,
    }


@app.post("/rooms/{room_id}/messages")
async def post_message(room_id: str, payload: SendMessageRequest) -> dict:
    """POST a message into a room (for non-WebSocket clients)."""
    room = _get_or_create_room(room_id)
    mentions = [w[1:] for w in payload.text.split() if w.startswith("@")]
    msg: Dict[str, Any] = {
        "type": "message",
        "room": room_id,
        "message_id": uuid.uuid4().hex,
        "username": payload.username,
        "text": payload.text,
        "mentions": mentions,
        "thread_id": payload.thread_id,
        "ts": datetime.utcnow().isoformat(),
    }
    room.add_message(msg)
    # Broadcast to connected WebSocket clients
    await room.broadcast(msg)
    return {"status": "sent", "message_id": msg["message_id"]}


@app.post("/rooms/{room_id}/scan-state")
async def update_scan_state(room_id: str, payload: ScanStateUpdate) -> dict:
    """Update the shared scan state for a room (REST version of the WS event)."""
    room = _get_or_create_room(room_id)
    state = {
        "status": payload.status,
        "progress": payload.progress,
        "findings_count": payload.findings_count,
    }
    room.scan_state = state
    await room.broadcast({
        "type": "scan_update",
        "room": room_id,
        "state": state,
        "updated_by": payload.updated_by,
        "ts": datetime.utcnow().isoformat(),
    })
    return {"room_id": room_id, "state": state}


@app.get("/activity-feed")
async def activity_feed(limit: int = 20) -> dict:
    """Global activity feed — latest messages across all rooms."""
    all_msgs: List[Dict[str, Any]] = []
    for room in _rooms.values():
        all_msgs.extend(room.messages)
    all_msgs.sort(key=lambda m: m.get("ts", ""), reverse=True)
    return {
        "feed": all_msgs[:limit],
        "total_events": len(all_msgs),
    }


    # ==========================================================================
    # Phase 2 — Collaborative Report Editing
    # ==========================================================================

    @app.post("/rooms/{room_id}/reports", status_code=201)
    async def create_report_section(room_id: str, payload: ReportSection) -> dict:
        """
        Create a new collaborative report section in this room.
        Broadcasts a 'report_update' event to all connected WebSocket clients.
        """
        section_id = payload.section_id or uuid.uuid4().hex
        now = datetime.utcnow().isoformat()
        section: Dict[str, Any] = {
            "section_id": section_id,
            "room_id": room_id,
            "title": payload.title,
            "content": payload.content,
            "author": payload.author,
            "section_type": payload.section_type,
            "created_at": now,
            "updated_at": now,
            "revision": 1,
            "edit_history": [],
        }
        _report_store[room_id][section_id] = section

        room = _get_or_create_room(room_id)
        await room.broadcast({
            "type": "report_update",
            "action": "created",
            "room": room_id,
            "section_id": section_id,
            "title": payload.title,
            "author": payload.author,
            "ts": now,
        })
        return section


    @app.get("/rooms/{room_id}/reports")
    async def list_report_sections(room_id: str, section_type: Optional[str] = None) -> dict:
        """List all collaborative report sections for this room."""
        sections = list(_report_store[room_id].values())
        if section_type:
            sections = [s for s in sections if s.get("section_type") == section_type]
        sections.sort(key=lambda s: s.get("created_at", ""))
        return {"room_id": room_id, "sections": sections, "total": len(sections)}


    @app.get("/rooms/{room_id}/reports/{section_id}")
    async def get_report_section(room_id: str, section_id: str) -> dict:
        """Fetch a single report section by ID."""
        from fastapi import HTTPException as _HTTPException
        section = _report_store[room_id].get(section_id)
        if section is None:
            raise _HTTPException(status_code=404, detail="Section not found")
        return section


    @app.put("/rooms/{room_id}/reports/{section_id}")
    async def update_report_section(room_id: str, section_id: str, payload: ReportSectionUpdate) -> dict:
        """
        Update an existing report section (collaborative edit).
        Saves a snapshot to edit_history and broadcasts a 'report_update' event.
        """
        from fastapi import HTTPException as _HTTPException
        section = _report_store[room_id].get(section_id)
        if section is None:
            raise _HTTPException(status_code=404, detail="Section not found")

        now = datetime.utcnow().isoformat()
        section["edit_history"].append({
            "revision": section["revision"],
            "title": section["title"],
            "content": section["content"],
            "updated_at": section["updated_at"],
            "editor": payload.editor,
        })
        # Keep last 20 revisions in memory
        section["edit_history"] = section["edit_history"][-20:]

        if payload.title is not None:
            section["title"] = payload.title
        if payload.content is not None:
            section["content"] = payload.content
        section["updated_at"] = now
        section["revision"] += 1

        room = _get_or_create_room(room_id)
        await room.broadcast({
            "type": "report_update",
            "action": "edited",
            "room": room_id,
            "section_id": section_id,
            "title": section["title"],
            "editor": payload.editor,
            "revision": section["revision"],
            "ts": now,
        })
        return section


    @app.delete("/rooms/{room_id}/reports/{section_id}")
    async def delete_report_section(room_id: str, section_id: str, editor: str = "api") -> dict:
        """Delete a report section and notify room members."""
        from fastapi import HTTPException as _HTTPException
        if _report_store[room_id].pop(section_id, None) is None:
            raise _HTTPException(status_code=404, detail="Section not found")

        room = _get_or_create_room(room_id)
        await room.broadcast({
            "type": "report_update",
            "action": "deleted",
            "room": room_id,
            "section_id": section_id,
            "editor": editor,
            "ts": datetime.utcnow().isoformat(),
        })
        return {"status": "deleted", "section_id": section_id}


    @app.get("/rooms/{room_id}/reports/{section_id}/history")
    async def get_section_history(room_id: str, section_id: str) -> dict:
        """Return the full edit history for a report section."""
        from fastapi import HTTPException as _HTTPException
        section = _report_store[room_id].get(section_id)
        if section is None:
            raise _HTTPException(status_code=404, detail="Section not found")
        return {
            "section_id": section_id,
            "current_revision": section["revision"],
            "history": section["edit_history"],
        }
