"""CosmicSec Integration Hub Service.

Provides connector endpoints for SIEM, ticketing, notifications, and external system forwarding.
"""
from __future__ import annotations

import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from fastapi import Depends, FastAPI
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from services.common.db import get_db
from services.common.models import IntegrationConfigModel

app = FastAPI(title="CosmicSec Integration Service", version="1.0.0")

# In-memory event logs (transient — forwarding audit trail)
siem_events: List[Dict[str, Any]] = []
tickets: List[Dict[str, Any]] = []
notifications: List[Dict[str, Any]] = []
webhook_events: List[Dict[str, Any]] = []

# Default forwarding endpoints (override via env)
SIEM_FORWARD_URL = os.getenv("SIEM_FORWARD_URL")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
PAGERDUTY_EVENTS_URL = os.getenv("PAGERDUTY_EVENTS_URL")
TWILIO_API_URL = os.getenv("TWILIO_API_URL")
JIRA_API_URL = os.getenv("JIRA_API_URL")
SERVICENOW_API_URL = os.getenv("SERVICENOW_API_URL")
GITHUB_ISSUES_API_URL = os.getenv("GITHUB_ISSUES_API_URL")
EMAIL_API_URL = os.getenv("EMAIL_API_URL")


class SIEMEvent(BaseModel):
    source: str
    severity: str = Field(default="info")
    message: str
    data: Optional[Dict[str, Any]] = None


class TicketCreate(BaseModel):
    project: str
    summary: str
    description: Optional[str] = None
    priority: Optional[str] = Field(default="Medium")
    labels: Optional[List[str]] = None


class NotificationRequest(BaseModel):
    channel: str
    message: str
    attributes: Optional[Dict[str, Any]] = None


class WebhookRequest(BaseModel):
    target_url: str
    event_type: str
    payload: Dict[str, Any]


class IntegrationConfigCreate(BaseModel):
    integration_type: str
    name: str
    config: Dict[str, Any] = Field(default_factory=dict)


async def _forward_post(url: Optional[str], payload: Dict[str, Any]) -> bool:
    if not url:
        return False
    async with httpx.AsyncClient() as client:
        try:
            await client.post(url, json=payload, timeout=5.0)
            return True
        except httpx.HTTPError:
            return False


def _notification_entry(notification_type: str, payload: NotificationRequest) -> Dict[str, Any]:
    return {
        "id": secrets.token_urlsafe(8),
        "type": notification_type,
        "channel": payload.channel,
        "message": payload.message,
        "attributes": payload.attributes or {},
        "sent_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/health")
async def health() -> dict:
    return {
        "status": "healthy",
        "service": "integration",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Integration config management (DB-backed)
# ---------------------------------------------------------------------------

@app.post("/configs", status_code=201)
async def create_integration_config(payload: IntegrationConfigCreate, db: Session = Depends(get_db)) -> dict:
    """Persist an integration configuration to the database."""
    config_id = f"cfg-{uuid.uuid4().hex[:8]}"
    record = IntegrationConfigModel(
        id=config_id,
        integration_type=payload.integration_type,
        name=payload.name,
        config=payload.config,
        is_active=True,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return _config_to_dict(record)


@app.get("/configs")
async def list_integration_configs(
    integration_type: Optional[str] = None,
    db: Session = Depends(get_db),
) -> dict:
    """List all stored integration configurations."""
    query = db.query(IntegrationConfigModel)
    if integration_type:
        query = query.filter(IntegrationConfigModel.integration_type == integration_type)
    configs = query.all()
    return {"configs": [_config_to_dict(c) for c in configs], "total": len(configs)}


@app.delete("/configs/{config_id}")
async def delete_integration_config(config_id: str, db: Session = Depends(get_db)) -> dict:
    from fastapi import HTTPException
    record = db.query(IntegrationConfigModel).filter(IntegrationConfigModel.id == config_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Config not found")
    db.delete(record)
    db.commit()
    return {"status": "deleted", "config_id": config_id}


@app.post("/siem/ingest")
async def ingest_siem(event: SIEMEvent) -> dict:
    """Ingest an event for SIEM consolidation or forwarding."""
    entry = {**event.model_dump(), "id": secrets.token_urlsafe(8), "received_at": datetime.now(timezone.utc).isoformat()}
    siem_events.append(entry)
    forwarded = await _forward_post(SIEM_FORWARD_URL, entry)
    return {"status": "stored", "event_id": entry["id"], "forwarded": forwarded}


@app.post("/siem/splunk")
async def ingest_splunk(event: SIEMEvent) -> dict:
    return await ingest_siem(SIEMEvent(source="splunk", severity=event.severity, message=event.message, data=event.data))


@app.post("/siem/qradar")
async def ingest_qradar(event: SIEMEvent) -> dict:
    return await ingest_siem(SIEMEvent(source="qradar", severity=event.severity, message=event.message, data=event.data))


@app.post("/siem/sentinel")
async def ingest_sentinel(event: SIEMEvent) -> dict:
    return await ingest_siem(SIEMEvent(source="sentinel", severity=event.severity, message=event.message, data=event.data))


@app.get("/siem/events")
async def list_siem_events(limit: int = 50) -> dict:
    return {"events": siem_events[-limit:], "total": len(siem_events)}


@app.post("/ticket/jira")
async def create_jira_ticket(ticket: TicketCreate) -> dict:
    issue_key = f"{ticket.project.upper()}-{secrets.randbelow(9999):04d}"
    entry = {
        "provider": "jira",
        "issue_key": issue_key,
        "summary": ticket.summary,
        "description": ticket.description,
        "priority": ticket.priority,
        "labels": ticket.labels or [],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    tickets.append(entry)
    forwarded = await _forward_post(JIRA_API_URL, entry)
    return {"status": "created", "issue_key": issue_key, "ticket": entry, "forwarded": forwarded}


@app.post("/ticket/servicenow")
async def create_servicenow_ticket(ticket: TicketCreate) -> dict:
    incident_id = f"INC{secrets.randbelow(9999999):07d}"
    entry = {
        "provider": "servicenow",
        "incident_id": incident_id,
        "project": ticket.project,
        "summary": ticket.summary,
        "description": ticket.description,
        "priority": ticket.priority,
        "labels": ticket.labels or [],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    tickets.append(entry)
    forwarded = await _forward_post(SERVICENOW_API_URL, entry)
    return {"status": "created", "incident_id": incident_id, "ticket": entry, "forwarded": forwarded}


@app.post("/ticket/github")
async def create_github_issue(ticket: TicketCreate) -> dict:
    issue_number = secrets.randbelow(90000) + 1000
    entry = {
        "provider": "github",
        "issue_number": issue_number,
        "repository": ticket.project,
        "title": ticket.summary,
        "body": ticket.description,
        "labels": ticket.labels or [],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    tickets.append(entry)
    forwarded = await _forward_post(GITHUB_ISSUES_API_URL, entry)
    return {"status": "created", "issue_number": issue_number, "ticket": entry, "forwarded": forwarded}


@app.post("/ticket/webhook")
async def create_ticket_webhook(payload: WebhookRequest) -> dict:
    entry = {
        "id": secrets.token_urlsafe(8),
        "event_type": payload.event_type,
        "target_url": payload.target_url,
        "payload": payload.payload,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    webhook_events.append(entry)
    forwarded = await _forward_post(payload.target_url, entry)
    return {"status": "queued", "webhook_id": entry["id"], "forwarded": forwarded}


@app.post("/notify/slack")
async def notify_slack(payload: NotificationRequest) -> dict:
    entry = _notification_entry("slack", payload)
    notifications.append(entry)
    forwarded = await _forward_post(SLACK_WEBHOOK_URL, {"text": payload.message})
    return {"status": "queued", "notification_id": entry["id"], "forwarded": forwarded}


@app.post("/notify/teams")
async def notify_teams(payload: NotificationRequest) -> dict:
    entry = _notification_entry("teams", payload)
    notifications.append(entry)
    forwarded = await _forward_post(TEAMS_WEBHOOK_URL, {"text": payload.message})
    return {"status": "queued", "notification_id": entry["id"], "forwarded": forwarded}


@app.post("/notify/discord")
async def notify_discord(payload: NotificationRequest) -> dict:
    entry = _notification_entry("discord", payload)
    notifications.append(entry)
    forwarded = await _forward_post(DISCORD_WEBHOOK_URL, {"content": payload.message})
    return {"status": "queued", "notification_id": entry["id"], "forwarded": forwarded}


@app.post("/notify/pagerduty")
async def notify_pagerduty(payload: NotificationRequest) -> dict:
    entry = _notification_entry("pagerduty", payload)
    notifications.append(entry)
    forwarded = await _forward_post(
        PAGERDUTY_EVENTS_URL,
        {"routing_key": "simulated", "event_action": "trigger", "payload": {"summary": payload.message}},
    )
    return {"status": "queued", "notification_id": entry["id"], "forwarded": forwarded}


@app.post("/notify/email")
async def notify_email(payload: NotificationRequest) -> dict:
    entry = _notification_entry("email", payload)
    notifications.append(entry)
    forwarded = await _forward_post(
        EMAIL_API_URL,
        {"to": payload.channel, "subject": payload.message[:64], "body": payload.message},
    )
    return {"status": "queued", "notification_id": entry["id"], "forwarded": forwarded}


@app.post("/notify/sms")
async def notify_sms(payload: NotificationRequest) -> dict:
    entry = _notification_entry("sms", payload)
    notifications.append(entry)
    forwarded = await _forward_post(TWILIO_API_URL, {"to": payload.channel, "body": payload.message})
    return {"status": "queued", "notification_id": entry["id"], "forwarded": forwarded}


@app.get("/threat-intel/ip")
async def threat_intel_ip(ip: str) -> dict:
    return {
        "ip": ip,
        "malicious": False,
        "risk_score": 12,
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "tags": ["scanner"],
        "notes": "Simulated threat intel response.",
    }


@app.get("/threat-intel/domain")
async def threat_intel_domain(domain: str) -> dict:
    return {
        "domain": domain,
        "malicious": False,
        "risk_score": 18,
        "last_seen": datetime.now(timezone.utc).isoformat(),
        "tags": ["phishing"],
        "notes": "Simulated threat intelligence lookup.",
    }


@app.post("/ci/build")
async def ci_build(trigger: Dict[str, Any]) -> dict:
    build_id = secrets.token_urlsafe(10)
    return {
        "status": "queued",
        "build_id": build_id,
        "trigger": trigger,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _config_to_dict(c: IntegrationConfigModel) -> dict:
    return {
        "config_id": c.id,
        "integration_type": c.integration_type,
        "name": c.name,
        "config": c.config,
        "is_active": c.is_active,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }
