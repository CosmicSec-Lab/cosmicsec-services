"""
CosmicSec Notification Service — Phase E event notifications.

Supports email (SMTP), Slack webhooks, and generic webhooks.
"""

from __future__ import annotations

import smtplib
import uuid
from datetime import UTC, datetime
from email.mime.text import MIMEText
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

app = FastAPI(
    title="CosmicSec Notification Service",
    description="Phase E — multi-channel event notification (email, Slack, webhook)",
    version="1.0.0",
)

# ---------------------------------------------------------------------------
# In-memory store
# ---------------------------------------------------------------------------
_configs: list[dict] = []

# Simple counters for Prometheus metrics
_metrics: dict[str, int] = {
    "notifications_sent_total": 0,
    "notification_errors_total": 0,
    "notification_configs_total": 0,
}

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class NotificationConfig(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    channel: str  # "email" | "slack" | "webhook"
    name: str
    config: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class NotificationEvent(BaseModel):
    event_type: str
    payload: dict[str, Any]
    channels: list[str] = Field(default_factory=list)


class TestNotificationRequest(BaseModel):
    config_id: str
    message: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _send_email(cfg: dict, subject: str, body: str) -> None:
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = cfg.get("smtp_user", "cosmicsec@localhost")
    msg["To"] = cfg.get("to_email", cfg.get("smtp_user", ""))
    host = cfg.get("smtp_host", "localhost")
    port = int(cfg.get("smtp_port", 587))
    user = cfg.get("smtp_user", "")
    password = cfg.get("smtp_pass", "")
    with smtplib.SMTP(host, port, timeout=10) as server:
        server.starttls()
        if user and password:
            server.login(user, password)
        server.send_message(msg)


def _send_slack(cfg: dict, text: str) -> None:
    url = cfg["webhook_url"]
    httpx.post(url, json={"text": text}, timeout=10)


def _send_webhook(cfg: dict, payload: dict) -> None:
    url = cfg["url"]
    httpx.post(url, json=payload, timeout=10)


def _dispatch(config: dict, event: NotificationEvent) -> None:
    channel = config["channel"]
    subject = f"[CosmicSec] {event.event_type}"
    body = str(event.payload)
    try:
        if channel == "email":
            _send_email(config["config"], subject, body)
        elif channel == "slack":
            _send_slack(config["config"], f"{subject}\n{body}")
        elif channel == "webhook":
            _send_webhook(
                config["config"], {"event_type": event.event_type, "payload": event.payload}
            )
        _metrics["notifications_sent_total"] += 1
    except Exception:
        _metrics["notification_errors_total"] += 1
        raise


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "notification"}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> str:
    lines = [
        "# HELP notifications_sent_total Total notifications sent successfully",
        "# TYPE notifications_sent_total counter",
        f"notifications_sent_total {_metrics['notifications_sent_total']}",
        "# HELP notification_errors_total Total notification send errors",
        "# TYPE notification_errors_total counter",
        f"notification_errors_total {_metrics['notification_errors_total']}",
        "# HELP notification_configs_total Total stored notification configurations",
        "# TYPE notification_configs_total gauge",
        f"notification_configs_total {_metrics['notification_configs_total']}",
    ]
    return "\n".join(lines) + "\n"


@app.post("/notify/config", response_model=NotificationConfig)
def create_config(cfg: NotificationConfig) -> NotificationConfig:
    """Save a notification channel configuration."""
    _configs.append(cfg.model_dump(mode="json"))
    _metrics["notification_configs_total"] = len(_configs)
    return cfg


@app.get("/notify/configs", response_model=list[NotificationConfig])
def list_configs() -> list[dict]:
    """List all stored notification configurations."""
    return _configs


@app.delete("/notify/configs/{config_id}")
def delete_config(config_id: str) -> dict:
    """Delete a notification configuration by id."""
    global _configs
    before = len(_configs)
    _configs = [c for c in _configs if c["id"] != config_id]
    if len(_configs) == before:
        raise HTTPException(status_code=404, detail=f"Config {config_id!r} not found")
    _metrics["notification_configs_total"] = len(_configs)
    return {"deleted": config_id}


@app.post("/notify/send")
def send_notification(event: NotificationEvent) -> dict:
    """Send a notification event to all matching channel configs."""
    errors: list[str] = []
    sent: list[str] = []

    target_configs = (
        [c for c in _configs if c["channel"] in event.channels] if event.channels else _configs
    )

    for config in target_configs:
        try:
            _dispatch(config, event)
            sent.append(config["id"])
        except Exception:
            errors.append(f"Failed to send to config {config['id']}")

    return {
        "sent": len(sent),
        "sent_ids": sent,
        "errors": errors,
    }


@app.post("/notify/test")
def test_notification(req: TestNotificationRequest) -> dict:
    """Send a test message to a specific config."""
    config = next((c for c in _configs if c["id"] == req.config_id), None)
    if not config:
        raise HTTPException(status_code=404, detail=f"Config {req.config_id!r} not found")

    event = NotificationEvent(
        event_type="test",
        payload={"message": req.message},
        channels=[config["channel"]],
    )
    try:
        _dispatch(config, event)
        return {"success": True, "config_id": req.config_id, "message": req.message}
    except Exception:
        return {
            "success": False,
            "config_id": req.config_id,
            "error": "Notification delivery failed",
        }
