"""SIEM connector — export audit logs to Splunk, Elastic SIEM, or flat files."""
from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)


def _to_cef(event: dict[str, Any]) -> str:
    """Convert an audit log event to CEF (Common Event Format) string."""
    timestamp = event.get("created_at", datetime.now(timezone.utc).isoformat())
    user_id = event.get("user_id", "unknown")
    action = event.get("action", "unknown")
    resource = event.get("resource", "")
    resource_id = event.get("resource_id", "")
    ip_address = event.get("ip_address", "")
    extra = json.dumps(event.get("extra") or {})

    header = f"CEF:0|CosmicSec|CosmicSec Platform|2.0|{action}|{action}|5|"
    ext = (
        f"rt={timestamp} suser={user_id} cs1={resource} cs1Label=resource "
        f"cs2={resource_id} cs2Label=resourceId src={ip_address} "
        f"cs3={extra} cs3Label=extra"
    )
    return header + ext


async def send_to_splunk(events: list[dict[str, Any]], hec_url: str, hec_token: str) -> bool:
    """Send audit events to Splunk HTTP Event Collector."""
    payload = "\n".join(
        json.dumps({"time": e.get("created_at", ""), "sourcetype": "cosmicsec:audit", "event": e})
        for e in events
    )
    headers = {"Authorization": f"Splunk {hec_token}", "Content-Type": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(hec_url, content=payload, headers=headers)
            resp.raise_for_status()
        return True
    except Exception as exc:
        logger.error("Splunk HEC send failed: %s", exc)
        return False


async def send_to_elastic_siem(events: list[dict[str, Any]], elastic_url: str, api_key: str) -> bool:
    """Send audit events to Elastic SIEM via Bulk API."""
    bulk_body = ""
    for ev in events:
        bulk_body += json.dumps({"index": {"_index": "cosmicsec-audit"}}) + "\n"
        bulk_body += json.dumps({**ev, "@timestamp": ev.get("created_at", "")}) + "\n"
    headers = {"Authorization": f"ApiKey {api_key}", "Content-Type": "application/x-ndjson"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(f"{elastic_url}/_bulk", content=bulk_body, headers=headers)
            resp.raise_for_status()
        return True
    except Exception as exc:
        logger.error("Elastic SIEM send failed: %s", exc)
        return False


def export_as_cef(events: list[dict[str, Any]]) -> str:
    """Export events as newline-separated CEF strings."""
    return "\n".join(_to_cef(e) for e in events)


def export_as_json(events: list[dict[str, Any]]) -> str:
    """Export events as a pretty-printed JSON array."""
    return json.dumps(events, indent=2, default=str)


def export_as_csv(events: list[dict[str, Any]]) -> str:
    """Export events as CSV."""
    fields = ["created_at", "user_id", "action", "resource", "resource_id", "ip_address"]
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for ev in events:
        writer.writerow({k: ev.get(k, "") for k in fields})
    return out.getvalue()
