"""
Scan Service Repository — SQLAlchemy CRUD operations for scans and findings.

Provides a DB-backed persistence layer with an in-memory LRU cache for active
scans.  The database is the source of truth; the cache accelerates real-time
WebSocket updates while a scan is running.
"""

from __future__ import annotations

import logging
import uuid
from collections import OrderedDict
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from services.common.models import FindingModel, ScanModel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory LRU cache for active scans (max 50 entries)
# ---------------------------------------------------------------------------
_MAX_CACHE_SIZE = 50


class _LRUCache(OrderedDict):
    """Simple thread-unsafe LRU cache backed by an :class:`OrderedDict`."""

    def __init__(self, maxsize: int = _MAX_CACHE_SIZE) -> None:
        super().__init__()
        self._maxsize = maxsize

    def get_or_none(self, key: str) -> dict | None:
        if key in self:
            self.move_to_end(key)
            return self[key]
        return None

    def put(self, key: str, value: dict) -> None:
        if key in self:
            self.move_to_end(key)
        self[key] = value
        if len(self) > self._maxsize:
            self.popitem(last=False)

    def evict(self, key: str) -> None:
        self.pop(key, None)


_scan_cache = _LRUCache()

# ---------------------------------------------------------------------------
# Helpers — dict ↔ ORM conversion
# ---------------------------------------------------------------------------


def _scan_to_dict(row: ScanModel) -> dict[str, Any]:
    return {
        "id": row.id,
        "user_id": row.user_id,
        "target": row.target,
        "scan_type": row.scan_type,
        "scan_types": [row.scan_type] if row.scan_type else [],
        "tool": row.tool,
        "status": row.status,
        "progress": row.progress,
        "source": row.source,
        "raw_output": row.raw_output,
        "summary": row.summary or {},
        "org_id": (row.summary or {}).get("org_id"),
        "workspace_id": (row.summary or {}).get("workspace_id"),
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "completed_at": row.completed_at,
        "started_at": (row.summary or {}).get("started_at"),
        "findings_count": (row.summary or {}).get("findings_count", 0),
        "severity_breakdown": (row.summary or {}).get("severity_breakdown", {}),
    }


def _finding_to_dict(row: FindingModel) -> dict[str, Any]:
    return {
        "id": row.id,
        "scan_id": row.scan_id,
        "title": row.title,
        "description": row.description,
        "severity": row.severity,
        "cvss_score": row.cvss_score,
        "category": row.tool or "general",
        "tool": row.tool,
        "target": row.target,
        "cve_id": row.cve_id,
        "evidence": row.evidence,
        "recommendation": (row.extra or {}).get("recommendation", ""),
        "detected_at": row.created_at,
        "created_at": row.created_at,
    }


# ---------------------------------------------------------------------------
# CRUD — Scans
# ---------------------------------------------------------------------------


def create_scan(db: Session, scan_data: dict[str, Any]) -> dict[str, Any]:
    """Insert a new scan into the database and warm the cache."""
    scan_id = scan_data.get("id") or f"scan-{uuid.uuid4().hex[:12]}"

    summary = {
        "org_id": scan_data.get("org_id"),
        "workspace_id": scan_data.get("workspace_id"),
        "started_at": None,
        "findings_count": 0,
        "severity_breakdown": {},
    }

    row = ScanModel(
        id=scan_id,
        user_id=scan_data.get("user_id"),
        target=scan_data["target"],
        scan_type=scan_data.get("scan_types", ["web"])[0] if scan_data.get("scan_types") else "web",
        status=scan_data.get("status", "pending"),
        progress=scan_data.get("progress", 0),
        source=scan_data.get("source", "web_scan"),
        summary=summary,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    result = _scan_to_dict(row)
    # Merge original scan_data keys that aren't stored directly in the ORM model
    result["scan_types"] = scan_data.get("scan_types", [result.get("scan_type", "web")])
    _scan_cache.put(scan_id, result)
    return result


def get_scan(db: Session, scan_id: str) -> dict[str, Any] | None:
    """Fetch a scan — cache first, then DB."""
    cached = _scan_cache.get_or_none(scan_id)
    if cached is not None:
        return cached

    row = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
    if row is None:
        return None

    result = _scan_to_dict(row)
    _scan_cache.put(scan_id, result)
    return result


def update_scan(db: Session, scan_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
    """Update scan fields in DB and cache."""
    row = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
    if row is None:
        return None

    if "status" in updates:
        row.status = updates["status"]
    if "progress" in updates:
        row.progress = updates["progress"]
    if "completed_at" in updates:
        row.completed_at = updates["completed_at"]
    if "raw_output" in updates:
        row.raw_output = updates["raw_output"]

    # Update summary JSON with extra fields
    summary = dict(row.summary or {})
    for key in ("started_at", "findings_count", "severity_breakdown", "org_id", "workspace_id"):
        if key in updates:
            summary[key] = updates[key]
    row.summary = summary

    db.commit()
    db.refresh(row)

    result = _scan_to_dict(row)
    _scan_cache.put(scan_id, result)
    return result


def list_scans(
    db: Session,
    status_filter: str | None = None,
    limit: int = 10,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """List scans with optional status filter and pagination."""
    query = db.query(ScanModel)
    if status_filter:
        query = query.filter(ScanModel.status == status_filter)
    query = query.order_by(ScanModel.created_at.desc())
    rows = query.offset(offset).limit(limit).all()
    return [_scan_to_dict(r) for r in rows]


def delete_scan(db: Session, scan_id: str) -> bool:
    """Delete scan and associated findings; evict from cache."""
    row = db.query(ScanModel).filter(ScanModel.id == scan_id).first()
    if row is None:
        return False

    db.query(FindingModel).filter(FindingModel.scan_id == scan_id).delete()
    db.delete(row)
    db.commit()
    _scan_cache.evict(scan_id)
    return True


def count_scans_today_for_org(db: Session, org_id: str) -> int:
    """Count scans created today for a given org (via summary->org_id)."""
    today = datetime.now(tz=UTC).date()
    # We use a broader query and filter in Python for JSON field access
    rows = (
        db.query(ScanModel)
        .filter(ScanModel.created_at >= datetime(today.year, today.month, today.day, tzinfo=UTC))
        .all()
    )
    return sum(1 for r in rows if (r.summary or {}).get("org_id") == org_id)


# ---------------------------------------------------------------------------
# CRUD — Findings
# ---------------------------------------------------------------------------


def create_finding(db: Session, finding_data: dict[str, Any]) -> dict[str, Any]:
    """Insert a finding into the database."""
    finding_id = finding_data.get("id") or f"find-{uuid.uuid4().hex[:12]}"

    row = FindingModel(
        id=finding_id,
        scan_id=finding_data.get("scan_id"),
        user_id=finding_data.get("user_id"),
        title=finding_data["title"],
        severity=finding_data.get("severity", "info"),
        description=finding_data.get("description"),
        evidence=finding_data.get("evidence"),
        tool=finding_data.get("category") or finding_data.get("tool"),
        target=finding_data.get("target"),
        cve_id=finding_data.get("cve_id"),
        cvss_score=finding_data.get("cvss_score"),
        source=finding_data.get("source", "web_scan"),
        extra={"recommendation": finding_data.get("recommendation", "")},
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _finding_to_dict(row)


def list_findings_for_scan(db: Session, scan_id: str) -> list[dict[str, Any]]:
    """Retrieve all findings belonging to a scan."""
    rows = (
        db.query(FindingModel)
        .filter(FindingModel.scan_id == scan_id)
        .order_by(FindingModel.created_at.desc())
        .all()
    )
    return [_finding_to_dict(r) for r in rows]


def count_findings(db: Session, scan_id: str | None = None) -> int:
    """Count findings, optionally filtered by scan_id."""
    query = db.query(FindingModel)
    if scan_id:
        query = query.filter(FindingModel.scan_id == scan_id)
    return query.count()


def get_severity_breakdown(db: Session, scan_id: str | None = None) -> dict[str, int]:
    """Return severity counts for findings."""
    query = db.query(FindingModel)
    if scan_id:
        query = query.filter(FindingModel.scan_id == scan_id)
    rows = query.all()
    breakdown: dict[str, int] = {}
    for r in rows:
        breakdown[r.severity] = breakdown.get(r.severity, 0) + 1
    return breakdown
