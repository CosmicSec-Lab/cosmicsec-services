"""
CosmicSec Notification Service — Phase E event notifications.

Supports email (SMTP), Slack, Discord, Telegram, generic webhooks,
Redis pub/sub, and SSH command channels.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import random
import smtplib
import time
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from email.mime.text import MIMEText
from typing import Any

import asyncssh
import httpx
import redis
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from services.common.security_utils import sanitize_for_log, validate_outbound_url

app = FastAPI(
    title="CosmicSec Notification Service",
    description=(
        "Phase E+ — multi-channel event notification "
        "(email, Slack, Discord, Telegram, webhook, Redis, SSH)"
    ),
    version="1.1.0",
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

_delivery_history: list[dict[str, Any]] = []
_DEAD_LETTER_WEBHOOK = os.getenv("NOTIFY_DEAD_LETTER_WEBHOOK", "").strip()
_SSH_RUNNING = 0

# policy profiles for channel orchestration / escalation
_policies: dict[str, dict[str, Any]] = {}

_CHANNELS: dict[str, dict[str, Any]] = {
    "email": {
        "required": ["smtp_host", "smtp_port", "smtp_user", "to_email"],
        "description": "SMTP email delivery",
    },
    "slack": {
        "required": ["webhook_url"],
        "description": "Slack incoming webhook",
    },
    "discord": {
        "required": ["webhook_url"],
        "description": "Discord channel webhook",
    },
    "telegram": {
        "required": ["bot_token", "chat_id"],
        "description": "Telegram bot sendMessage API",
    },
    "webhook": {
        "required": ["url"],
        "description": "Custom HTTP webhook endpoint",
    },
    "redis_pubsub": {
        "required": ["channel"],
        "description": "Redis Pub/Sub publish channel",
    },
    "ssh_command": {
        "required": ["host", "username", "command"],
        "description": "Execute formatted command over SSH",
    },
    "redis_streams": {
        "required": ["stream"],
        "description": "Redis Streams event append",
    },
    "teams": {
        "required": ["webhook_url"],
        "description": "Microsoft Teams incoming webhook",
    },
    "google_chat": {
        "required": ["webhook_url"],
        "description": "Google Chat incoming webhook",
    },
    "matrix": {
        "required": ["homeserver", "access_token", "room_id"],
        "description": "Matrix room message delivery",
    },
    "nats": {
        "required": ["subject"],
        "description": "NATS publish channel (optional dependency)",
    },
}

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class NotificationConfig(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    channel: str
    name: str
    enabled: bool = True
    tags: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class NotificationEvent(BaseModel):
    event_type: str
    severity: str = "info"
    subject: str | None = None
    payload: dict[str, Any]
    channels: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class TestNotificationRequest(BaseModel):
    config_id: str
    message: str


class ValidateConfigRequest(BaseModel):
    channel: str
    config: dict[str, Any] = Field(default_factory=dict)


class BatchNotificationRequest(BaseModel):
    events: list[NotificationEvent] = Field(default_factory=list)


class PolicyProfile(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    enabled: bool = True
    severities: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    channels: list[str] = Field(default_factory=list)
    escalation_chain: list[list[str]] = Field(default_factory=list)


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


def _safe_public_url(url: str, *, allow_private_hosts: bool = False) -> str:
    validated = validate_outbound_url(
        url,
        allow_private_hosts=allow_private_hosts,
        require_https=not allow_private_hosts,
    )
    if not validated:
        raise ValueError("unsafe or invalid URL")
    return validated


def _event_payload(event: NotificationEvent) -> dict[str, Any]:
    return {
        "event_type": event.event_type,
        "severity": event.severity,
        "subject": event.subject,
        "payload": event.payload,
        "tags": event.tags,
        "timestamp": datetime.now(UTC).isoformat(),
    }


def _event_text(event: NotificationEvent) -> str:
    subject = event.subject or f"[CosmicSec] {event.event_type}"
    payload_text = json.dumps(event.payload, ensure_ascii=True, indent=2, default=str)
    return f"{subject}\nSeverity: {event.severity}\n\n{payload_text}"


def _escape_markdown_v2(text: str) -> str:
    """Escape Telegram MarkdownV2 reserved characters."""
    reserved = r"_ * [ ] ( ) ~ ` > # + - = | { } . !".split()
    out = text
    for ch in reserved:
        out = out.replace(ch, f"\\{ch}")
    return out


def _send_slack(cfg: dict, text: str) -> None:
    url = _safe_public_url(cfg["webhook_url"])
    httpx.post(url, json={"text": text}, timeout=10)


def _send_discord(cfg: dict, event: NotificationEvent, text: str) -> None:
    url = _safe_public_url(cfg["webhook_url"])
    embed_color = {
        "critical": 0xF43F5E,
        "high": 0xFB923C,
        "medium": 0xFACC15,
        "low": 0x22D3EE,
        "info": 0x64748B,
    }.get(event.severity.lower(), 0x64748B)
    payload = {
        "content": cfg.get("prefix", ""),
        "embeds": [
            {
                "title": event.subject or f"CosmicSec: {event.event_type}",
                "description": text[:1800],
                "color": embed_color,
            }
        ],
    }
    httpx.post(url, json=payload, timeout=10)


def _send_telegram(cfg: dict, text: str) -> None:
    token = cfg["bot_token"]
    chat_id = str(cfg["chat_id"])
    api_url = _safe_public_url(f"https://api.telegram.org/bot{token}/sendMessage")
    parse_mode = cfg.get("parse_mode", "Markdown")
    if parse_mode == "MarkdownV2":
        text = _escape_markdown_v2(text)

    payload = {
        "chat_id": chat_id,
        "text": text[:3900],
        "disable_web_page_preview": True,
        "parse_mode": parse_mode,
    }
    httpx.post(api_url, json=payload, timeout=10)


def _send_dead_letter(config: dict, event: NotificationEvent, error: Exception) -> None:
    if not _DEAD_LETTER_WEBHOOK:
        return

    try:
        url = _safe_public_url(_DEAD_LETTER_WEBHOOK)
        payload = {
            "event_type": "notification.dead_letter",
            "timestamp": datetime.now(UTC).isoformat(),
            "failed_config": {
                "id": config.get("id"),
                "name": config.get("name"),
                "channel": config.get("channel"),
            },
            "original_event": _event_payload(event),
            "error": sanitize_for_log(error),
        }
        httpx.post(url, json=payload, timeout=10)
    except Exception:
        # Avoid cascading failures from dead-letter handler.
        pass


def _send_webhook(cfg: dict, payload: dict) -> None:
    url = _safe_public_url(cfg["url"], allow_private_hosts=bool(cfg.get("allow_private_hosts")))
    method = str(cfg.get("method", "POST")).upper()
    headers = cfg.get("headers", {})
    if method not in {"POST", "PUT", "PATCH"}:
        raise ValueError("webhook method must be POST, PUT, or PATCH")

    # Optional request signing and replay-window timestamp support.
    webhook_secret = str(cfg.get("webhook_secret", "")).strip()
    timestamp = str(int(time.time()))
    headers = {**headers, "X-CosmicSec-Timestamp": timestamp}
    if webhook_secret:
        body_bytes = json.dumps(payload, ensure_ascii=True, sort_keys=True, default=str).encode("utf-8")
        sig = hmac.new(webhook_secret.encode("utf-8"), timestamp.encode("utf-8") + b"." + body_bytes, hashlib.sha256).hexdigest()
        headers["X-CosmicSec-Signature"] = f"sha256={sig}"

    httpx.request(method, url, json=payload, headers=headers, timeout=10)


def _send_redis_pubsub(cfg: dict, payload: dict) -> None:
    channel = cfg["channel"]
    message = json.dumps(payload, ensure_ascii=True, default=str)

    if cfg.get("redis_url"):
        client = redis.Redis.from_url(cfg["redis_url"], decode_responses=True)
    else:
        client = redis.Redis(
            host=cfg.get("host", "localhost"),
            port=int(cfg.get("port", 6379)),
            db=int(cfg.get("db", 0)),
            password=cfg.get("password"),
            decode_responses=True,
            socket_timeout=5,
        )

    try:
        client.publish(channel, message)
    finally:
        client.close()


def _redis_client_from_cfg(cfg: dict) -> redis.Redis:
    if cfg.get("redis_url"):
        return redis.Redis.from_url(cfg["redis_url"], decode_responses=True)
    return redis.Redis(
        host=cfg.get("host", "localhost"),
        port=int(cfg.get("port", 6379)),
        db=int(cfg.get("db", 0)),
        password=cfg.get("password"),
        decode_responses=True,
        socket_timeout=5,
    )


def _send_redis_streams(cfg: dict, payload: dict) -> None:
    stream = cfg["stream"]
    maxlen = int(cfg.get("maxlen", 10000))
    message = {"event": json.dumps(payload, ensure_ascii=True, default=str)}
    client = _redis_client_from_cfg(cfg)
    try:
        client.xadd(stream, message, maxlen=maxlen, approximate=True)
    finally:
        client.close()


def _send_teams(cfg: dict, text: str) -> None:
    url = _safe_public_url(cfg["webhook_url"])
    httpx.post(url, json={"text": text[:3800]}, timeout=10)


def _send_google_chat(cfg: dict, text: str) -> None:
    url = _safe_public_url(cfg["webhook_url"])
    httpx.post(url, json={"text": text[:3800]}, timeout=10)


def _send_matrix(cfg: dict, event: NotificationEvent, text: str) -> None:
    homeserver = str(cfg["homeserver"]).rstrip("/")
    token = str(cfg["access_token"])
    room_id = str(cfg["room_id"])
    txn_id = f"cosmicsec-{uuid.uuid4().hex}"
    url = _safe_public_url(
        f"{homeserver}/_matrix/client/v3/rooms/{room_id}/send/m.room.message/{txn_id}",
        allow_private_hosts=bool(cfg.get("allow_private_hosts", False)),
    )
    headers = {"Authorization": f"Bearer {token}"}
    body = {
        "msgtype": "m.text",
        "body": text[:3900],
        "format": "org.matrix.custom.html",
        "formatted_body": f"<b>{event.subject or event.event_type}</b><br/><pre>{text[:3000]}</pre>",
    }
    httpx.put(url, json=body, headers=headers, timeout=10)


def _send_nats(cfg: dict, payload: dict) -> None:
    try:
        import nats  # type: ignore[import-not-found]
    except Exception as exc:
        raise ValueError("nats dependency not installed") from exc

    async def _publish() -> None:
        servers = cfg.get("servers", ["nats://127.0.0.1:4222"])
        subject = str(cfg["subject"])
        nc = await nats.connect(servers=servers)
        try:
            await nc.publish(subject, json.dumps(payload, ensure_ascii=True, default=str).encode("utf-8"))
            await nc.flush(timeout=2)
        finally:
            await nc.close()

    asyncio.run(_publish())


async def _run_ssh_command(cfg: dict, event: NotificationEvent, text: str) -> str:
    global _SSH_RUNNING

    max_concurrency = int(cfg.get("max_concurrency", 2))
    if _SSH_RUNNING >= max_concurrency:
        raise ValueError("ssh command concurrency limit reached")

    command_template = cfg["command"]
    command = command_template.format(
        event_type=event.event_type,
        severity=event.severity,
        subject=event.subject or f"CosmicSec {event.event_type}",
        payload_json=json.dumps(event.payload, ensure_ascii=True, default=str),
        message=text.replace("\n", " | "),
    )

    allow_templates = cfg.get("allowed_command_templates", [])
    if allow_templates and command_template not in allow_templates:
        raise ValueError("command template is not allow-listed")

    max_runtime = int(cfg.get("max_runtime_s", 15))

    connect_kwargs: dict[str, Any] = {
        "host": cfg["host"],
        "port": int(cfg.get("port", 22)),
        "username": cfg["username"],
        "known_hosts": (
            None
            if cfg.get("ignore_host_key", False)
            else cfg.get("known_hosts", os.path.expanduser("~/.ssh/known_hosts"))
        ),
    }

    if cfg.get("password"):
        connect_kwargs["password"] = cfg["password"]
    if cfg.get("client_keys"):
        connect_kwargs["client_keys"] = cfg["client_keys"]

    _SSH_RUNNING += 1
    try:
        async with asyncssh.connect(**connect_kwargs) as conn:
            result = await asyncio.wait_for(conn.run(command, check=True), timeout=max_runtime)
            return result.stdout.strip()
    finally:
        _SSH_RUNNING -= 1


def _send_ssh_command(cfg: dict, event: NotificationEvent, text: str) -> None:
    asyncio.run(_run_ssh_command(cfg, event, text))


def _validate_channel_config(channel: str, cfg: Mapping[str, Any]) -> None:
    channel_meta = _CHANNELS.get(channel)
    if not channel_meta:
        raise HTTPException(status_code=422, detail=f"Unsupported channel: {channel}")

    missing = [key for key in channel_meta["required"] if not str(cfg.get(key, "")).strip()]
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"Missing required config keys for {channel}: {', '.join(missing)}",
        )

    # replay-window sanity for signed webhooks
    if channel in {"webhook", "slack", "discord", "teams", "google_chat"}:
        if cfg.get("webhook_secret") and int(cfg.get("replay_window_s", 300)) < 30:
            raise HTTPException(status_code=422, detail="replay_window_s must be >= 30 when webhook_secret is set")


def _record_delivery(
    *,
    config: dict[str, Any],
    event: NotificationEvent,
    success: bool,
    error: str | None = None,
) -> None:
    _delivery_history.append(
        {
            "timestamp": datetime.now(UTC).isoformat(),
            "config_id": config["id"],
            "config_name": config.get("name", ""),
            "channel": config["channel"],
            "event_type": event.event_type,
            "severity": event.severity,
            "success": success,
            "error": sanitize_for_log(error) if error else None,
            "latency_ms": int(config.get("_last_latency_ms", 0)),
        }
    )
    # keep the in-memory history bounded
    if len(_delivery_history) > 2000:
        del _delivery_history[: len(_delivery_history) - 2000]


def _dispatch(config: dict, event: NotificationEvent) -> None:
    channel = config["channel"]
    cfg = config["config"]
    subject = event.subject or f"[CosmicSec] {event.event_type}"
    body = _event_text(event)
    payload = _event_payload(event)

    started = time.perf_counter()
    try:
        if channel == "email":
            _send_email(cfg, subject, body)
        elif channel == "slack":
            _send_slack(cfg, f"{subject}\n{body}")
        elif channel == "discord":
            _send_discord(cfg, event, body)
        elif channel == "telegram":
            _send_telegram(cfg, body)
        elif channel == "webhook":
            _send_webhook(cfg, payload)
        elif channel == "redis_pubsub":
            _send_redis_pubsub(cfg, payload)
        elif channel == "redis_streams":
            _send_redis_streams(cfg, payload)
        elif channel == "ssh_command":
            _send_ssh_command(cfg, event, body)
        elif channel == "teams":
            _send_teams(cfg, body)
        elif channel == "google_chat":
            _send_google_chat(cfg, body)
        elif channel == "matrix":
            _send_matrix(cfg, event, body)
        elif channel == "nats":
            _send_nats(cfg, payload)
        else:
            raise ValueError(f"Unsupported channel {channel}")

        config["_last_latency_ms"] = int((time.perf_counter() - started) * 1000)
        _metrics["notifications_sent_total"] += 1
    except (
        smtplib.SMTPException,
        httpx.HTTPError,
        OSError,
        ValueError,
        redis.RedisError,
        asyncssh.Error,
    ):
        _metrics["notification_errors_total"] += 1
        raise


def _dispatch_with_retry(config: dict, event: NotificationEvent) -> None:
    cfg = config.get("config", {})
    max_retries = int(cfg.get("max_retries", 0))
    base_delay_ms = int(cfg.get("base_delay_ms", 200))
    jitter_ms = int(cfg.get("jitter_ms", 150))

    attempt = 0
    while True:
        try:
            _dispatch(config, event)
            return
        except (
            smtplib.SMTPException,
            httpx.HTTPError,
            OSError,
            ValueError,
            redis.RedisError,
            asyncssh.Error,
        ) as exc:
            if attempt >= max_retries:
                _send_dead_letter(config, event, exc)
                raise

            delay_ms = base_delay_ms * (2**attempt) + random.randint(0, max(0, jitter_ms))
            time.sleep(delay_ms / 1000)
            attempt += 1


def _channels_from_policies(event: NotificationEvent) -> list[str]:
    ordered: list[str] = []
    for policy in _policies.values():
        if not policy.get("enabled", True):
            continue

        policy_severities = [s.lower() for s in policy.get("severities", [])]
        if policy_severities and event.severity.lower() not in policy_severities:
            continue

        policy_tags = set(policy.get("tags", []))
        if policy_tags and not (policy_tags & set(event.tags)):
            continue

        for ch in policy.get("channels", []):
            if ch not in ordered:
                ordered.append(ch)
        for group in policy.get("escalation_chain", []):
            for ch in group:
                if ch not in ordered:
                    ordered.append(ch)

    return ordered


def _percentile(values: list[int], pct: float) -> int:
    if not values:
        return 0
    sorted_vals = sorted(values)
    k = int((len(sorted_vals) - 1) * pct)
    return sorted_vals[k]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "notification",
        "supported_channels": sorted(_CHANNELS.keys()),
    }


@app.get("/notify/channels")
def list_supported_channels() -> dict[str, Any]:
    return {"channels": _CHANNELS}


@app.post("/notify/config/validate")
def validate_config(payload: ValidateConfigRequest) -> dict[str, Any]:
    _validate_channel_config(payload.channel, payload.config)
    return {
        "valid": True,
        "channel": payload.channel,
        "required": _CHANNELS[payload.channel]["required"],
    }


@app.post("/notify/policies")
def create_policy(policy: PolicyProfile) -> PolicyProfile:
    _policies[policy.id] = policy.model_dump(mode="json")
    return policy


@app.get("/notify/policies")
def list_policies() -> dict[str, Any]:
    return {"items": list(_policies.values())}


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
    _validate_channel_config(cfg.channel, cfg.config)
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


@app.post("/notify/configs/{config_id}/enable")
def enable_config(config_id: str) -> dict[str, Any]:
    for config in _configs:
        if config["id"] == config_id:
            config["enabled"] = True
            return {"id": config_id, "enabled": True}
    raise HTTPException(status_code=404, detail=f"Config {config_id!r} not found")


@app.post("/notify/configs/{config_id}/disable")
def disable_config(config_id: str) -> dict[str, Any]:
    for config in _configs:
        if config["id"] == config_id:
            config["enabled"] = False
            return {"id": config_id, "enabled": False}
    raise HTTPException(status_code=404, detail=f"Config {config_id!r} not found")


@app.post("/notify/send")
def send_notification(event: NotificationEvent) -> dict:
    """Send a notification event to all matching channel configs."""
    errors: list[dict[str, str]] = []
    sent: list[dict[str, str]] = []

    target_configs = [c for c in _configs if c.get("enabled", True)]
    routed_channels = event.channels or _channels_from_policies(event)
    if routed_channels:
        target_configs = [c for c in target_configs if c["channel"] in routed_channels]
    if event.tags:
        target_configs = [
            c
            for c in target_configs
            if not c.get("tags") or set(c.get("tags", [])) & set(event.tags)
        ]

    for config in target_configs:
        try:
            _dispatch_with_retry(config, event)
            _record_delivery(config=config, event=event, success=True)
            sent.append(
                {
                    "id": config["id"],
                    "channel": config["channel"],
                    "name": config["name"],
                }
            )
        except (
            smtplib.SMTPException,
            httpx.HTTPError,
            OSError,
            ValueError,
            redis.RedisError,
            asyncssh.Error,
        ) as exc:
            _record_delivery(config=config, event=event, success=False, error=str(exc))
            errors.append(
                {
                    "id": config["id"],
                    "channel": config["channel"],
                    "error": sanitize_for_log(exc),
                }
            )

    return {
        "sent": len(sent),
        "sent_configs": sent,
        "errors": errors,
        "routed_channels": routed_channels,
    }


@app.post("/notify/send/batch")
def send_batch_notifications(payload: BatchNotificationRequest) -> dict[str, Any]:
    if not payload.events:
        raise HTTPException(status_code=422, detail="events list cannot be empty")

    results = []
    total_sent = 0
    total_errors = 0

    for event in payload.events:
        result = send_notification(event)
        results.append({"event_type": event.event_type, **result})
        total_sent += int(result.get("sent", 0))
        total_errors += len(result.get("errors", []))

    return {
        "events": len(payload.events),
        "total_sent": total_sent,
        "total_errors": total_errors,
        "results": results,
    }


@app.get("/notify/delivery/history")
def get_delivery_history(limit: int = 100) -> dict[str, Any]:
    safe_limit = max(1, min(limit, 500))
    return {
        "count": min(safe_limit, len(_delivery_history)),
        "items": list(reversed(_delivery_history[-safe_limit:])),
    }


@app.get("/notify/analytics")
def get_delivery_analytics() -> dict[str, Any]:
    if not _delivery_history:
        return {
            "total": 0,
            "success_rate": 0.0,
            "latency_ms": {"p50": 0, "p95": 0, "p99": 0},
            "channel_reliability": {},
        }

    total = len(_delivery_history)
    successes = sum(1 for item in _delivery_history if item.get("success"))
    latencies = [int(item.get("latency_ms", 0)) for item in _delivery_history]
    by_channel: dict[str, dict[str, int]] = {}
    for item in _delivery_history:
        channel = str(item.get("channel", "unknown"))
        by_channel.setdefault(channel, {"total": 0, "success": 0})
        by_channel[channel]["total"] += 1
        if item.get("success"):
            by_channel[channel]["success"] += 1

    reliability = {
        channel: {
            "total": meta["total"],
            "success": meta["success"],
            "success_rate": round((meta["success"] / meta["total"]) * 100, 2) if meta["total"] else 0.0,
        }
        for channel, meta in by_channel.items()
    }

    return {
        "total": total,
        "success_rate": round((successes / total) * 100, 2),
        "latency_ms": {
            "p50": _percentile(latencies, 0.50),
            "p95": _percentile(latencies, 0.95),
            "p99": _percentile(latencies, 0.99),
        },
        "channel_reliability": reliability,
    }


@app.post("/notify/test")
def test_notification(req: TestNotificationRequest) -> dict:
    """Send a test message to a specific config."""
    config = next((c for c in _configs if c["id"] == req.config_id), None)
    if not config:
        raise HTTPException(status_code=404, detail=f"Config {req.config_id!r} not found")

    event = NotificationEvent(
        event_type="test",
        severity="info",
        subject="CosmicSec test notification",
        payload={"message": req.message},
        channels=[config["channel"]],
    )
    try:
        _dispatch_with_retry(config, event)
        return {"success": True, "config_id": req.config_id, "message": req.message}
    except (
        smtplib.SMTPException,
        httpx.HTTPError,
        OSError,
        ValueError,
        redis.RedisError,
        asyncssh.Error,
    ):
        return {
            "success": False,
            "config_id": req.config_id,
            "error": "Notification delivery failed",
        }
