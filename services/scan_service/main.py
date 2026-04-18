"""
CosmicSec Scan Service
Handles security scanning operations with distributed task processing
"""

import gzip
import json
import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

import httpx
from fastapi import (
    BackgroundTasks,
    FastAPI,
    HTTPException,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import text

from cosmicsec_platform.service_discovery import get_service_url
from services.common.db import SessionLocal
from services.common.egress import EgressOptions
from services.common.models import FindingModel
from services.common.observability import setup_observability

try:
    from jose import JWTError, jwt
except ImportError:  # pragma: no cover
    JWTError = Exception  # type: ignore[misc,assignment]
    jwt = None

try:
    from celery import Celery
except ImportError:  # pragma: no cover
    Celery = None

try:
    from pymongo import MongoClient
except ImportError:  # pragma: no cover
    MongoClient = None

# Phase 2 modules
from .api_fuzzer import APIFuzzer
from .container_scanner import scan_container_artifact
from .continuous_monitor import ContinuousMonitor
from .distributed_scanner import DistributedScanCoordinator
from .repository import (
    count_findings,
    count_scans_today_for_org,
    create_finding,
    get_severity_breakdown,
    list_findings_for_scan,
)
from .repository import (
    create_scan as db_create_scan,
)
from .repository import (
    delete_scan as db_delete_scan,
)
from .repository import (
    get_scan as db_get_scan,
)
from .repository import (
    list_scans as db_list_scans,
)
from .repository import (
    update_scan as db_update_scan,
)
from .smart_scanner import smart_scan

# Module-level monitor singleton — started on app startup
_monitor = ContinuousMonitor()
_distributed = DistributedScanCoordinator()


@asynccontextmanager
async def _lifespan(fastapi_app: "FastAPI"):
    await _monitor.start()
    yield
    await _monitor.stop()


app = FastAPI(
    title="CosmicSec Scan Service",
    description="Security scanning service with Helix AI analysis — Phase 2",
    version="2.0.0",
    lifespan=_lifespan,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
_observability_state = setup_observability(app, service_name="scan-service", logger=logger)


# Enums
class ScanType(StrEnum):
    NETWORK = "network"
    WEB = "web"
    API = "api"
    CLOUD = "cloud"
    CONTAINER = "container"


class ScanStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


# Data models
class ScanConfig(BaseModel):
    target: str = Field(..., description="Target URL, IP, or domain")
    scan_types: list[ScanType] = Field(..., description="Types of scans to perform")
    depth: int = Field(default=1, ge=1, le=5, description="Scan depth (1-5)")
    timeout: int = Field(default=300, ge=60, le=3600, description="Timeout in seconds")
    options: dict | None = Field(default={}, description="Additional scan options")


def _normalize_tor_mode(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    mode = value.strip().lower()
    if mode in {"enabled", "disabled", "auto"}:
        return mode
    return None


def _egress_options_from_payload(payload: dict[str, Any] | None) -> EgressOptions | None:
    source = payload or {}
    tor_mode = _normalize_tor_mode(source.get("tor_mode"))
    return EgressOptions(
        use_proxy_pool=bool(source.get("use_proxy_pool", False)),
        proxy_url=source.get("proxy_url"),
        rotate_identity=bool(source.get("rotate_identity", False)),
        client_profile=source.get("client_profile"),
        use_tor=bool(source.get("use_tor", False)),
        tor_mode=tor_mode,
    )


class Scan(BaseModel):
    id: str
    target: str
    scan_types: list[ScanType]
    status: ScanStatus
    created_at: datetime
    org_id: str | None = None
    workspace_id: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    progress: int = 0
    findings_count: int = 0
    severity_breakdown: dict[str, int] = {}


class Finding(BaseModel):
    id: str
    scan_id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    cvss_score: float | None = None
    category: str
    recommendation: str
    detected_at: datetime


# Legacy in-memory storage — kept as hot cache / backward compat for tests
# All writes now go through the repository (DB-backed); these dicts act as
# fast-path caches that are populated on read and invalidated on write.
scans_db: dict[str, Any] = {}
findings_db: list[dict[str, Any]] = []

# Optional in-service quota override (used when auth service is not reachable)
tenant_quotas: dict[str, dict[str, int]] = {}


async def _fetch_org_quotas(org_id: str) -> dict[str, int]:
    """Fetch tenant quota settings from the auth service (fallback to in-memory)."""
    if org_id in tenant_quotas:
        return tenant_quotas[org_id]

    try:
        async with httpx.AsyncClient() as client:
            auth_url = _get_auth_service_url()
            resp = await client.get(f"{auth_url}/orgs/{org_id}/quotas", timeout=5.0)
            if resp.status_code == 200:
                return resp.json().get("quotas", {})
    except httpx.HTTPError:
        pass
    return {}


def _scans_today_for_org(org_id: str) -> int:
    today = datetime.now(tz=UTC).date()
    return sum(
        1
        for scan in scans_db.values()
        if scan.get("org_id") == org_id
        and isinstance(scan.get("created_at"), datetime)
        and scan["created_at"].date() == today
    )


def _load_scan_from_cache_or_db(scan_id: str) -> dict[str, Any] | None:
    """Fetch scan from in-memory cache first, then DB and rehydrate cache."""
    cached = scans_db.get(scan_id)
    if cached is not None:
        return cached
    try:
        db = SessionLocal()
        row = db_get_scan(db, scan_id)
        db.close()
        if row:
            scans_db[scan_id] = row
            return row
    except Exception:
        logger.warning("DB read failed for scan %s", scan_id, exc_info=True)
    return None


celery_app = None
if Celery is not None:
    broker_url = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
    backend_url = os.getenv("CELERY_BACKEND_URL", "redis://redis:6379/0")
    celery_app = Celery("cosmicsec_scan", broker=broker_url, backend=backend_url)
    celery_app.conf.timezone = "UTC"
    celery_app.conf.beat_schedule = {
        "refresh-dashboard-stats-view": {
            "task": "scan_service.refresh_dashboard_stats_view",
            "schedule": 300.0,
        }
    }


def _refresh_dashboard_stats_view() -> bool:
    """Refresh Phase S dashboard materialized view when available."""
    db = SessionLocal()
    try:
        db.execute(text("REFRESH MATERIALIZED VIEW CONCURRENTLY dashboard_stats"))
        db.commit()
        return True
    except Exception:
        db.rollback()
        try:
            db.execute(text("REFRESH MATERIALIZED VIEW dashboard_stats"))
            db.commit()
            return True
        except Exception:
            db.rollback()
            logger.warning("Dashboard materialized view refresh failed", exc_info=True)
            return False
    finally:
        db.close()


if celery_app is not None:

    @celery_app.task(name="scan_service.refresh_dashboard_stats_view")
    def refresh_dashboard_stats_view_task() -> dict[str, bool]:
        ok = _refresh_dashboard_stats_view()
        return {"ok": ok}


mongo_collection = None
if MongoClient is not None:
    try:
        mongo_client = MongoClient(
            os.getenv("MONGO_URI", "mongodb://mongodb:27017"), serverSelectionTimeoutMS=2000
        )
        mongo_collection = mongo_client["cosmicsec"]["scan_results"]
    except Exception:
        mongo_collection = None


# Service discovery - auto-detects OS and deployment environment
def _get_auth_service_url() -> str:
    """Get Auth Service URL based on deployment environment."""
    # Check for explicit override first
    if explicit_url := os.getenv("AUTH_SERVICE_URL"):
        return explicit_url
    # Use service discovery (handles Windows/Linux/macOS automatically)
    return get_service_url("auth")


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: dict[str, list[WebSocket]] = {}

    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.setdefault(scan_id, []).append(websocket)

    def disconnect(self, scan_id: str, websocket: WebSocket) -> None:
        self.active_connections[scan_id] = [
            ws for ws in self.active_connections.get(scan_id, []) if ws != websocket
        ]

    async def broadcast(self, scan_id: str, message: dict) -> None:
        for ws in self.active_connections.get(scan_id, []):
            await ws.send_json(message)


ws_manager = ConnectionManager()

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")


def _validate_ws_token(token: str | None) -> dict[str, Any] | None:
    if not token or not JWT_SECRET_KEY or jwt is None:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None
    sub = payload.get("sub") or payload.get("user_id")
    if not sub:
        return None
    return payload


async def perform_scan(scan_id: str, config: ScanConfig):
    """Background task to perform the actual scan"""
    scan = _load_scan_from_cache_or_db(scan_id)
    if scan is None:
        logger.error("Scan %s not found", scan_id)
        return

    try:
        def _is_cancelled() -> bool:
            return str(scan.get("status", "")).lower() == ScanStatus.CANCELLED.value

        if _is_cancelled():
            return

        # Update status
        scan["status"] = ScanStatus.RUNNING
        scan["started_at"] = datetime.now(tz=UTC)

        # Persist status change to DB
        try:
            db = SessionLocal()
            db_update_scan(db, scan_id, {"status": "running", "started_at": scan["started_at"]})
            db.close()
        except Exception:
            logger.warning("DB update failed for scan %s status change", scan_id, exc_info=True)

        await ws_manager.broadcast(
            scan_id, {"scan_id": scan_id, "status": "running", "progress": 0}
        )

        # Simulate scanning process
        logger.info(f"Starting scan {scan_id} for target {config.target}")

        # Network scan simulation
        if ScanType.NETWORK in config.scan_types:
            if _is_cancelled():
                return
            scan["progress"] = 25
            await ws_manager.broadcast(
                scan_id, {"scan_id": scan_id, "status": "running", "progress": 25}
            )
            logger.info(f"Scan {scan_id}: Network scan in progress...")

            finding_data = {
                "id": secrets.token_urlsafe(16),
                "scan_id": scan_id,
                "title": "Open Port Detected",
                "description": "Port 22 (SSH) is open and accessible",
                "severity": "medium",
                "cvss_score": 5.3,
                "category": "network",
                "recommendation": "Implement IP whitelisting for SSH access",
                "detected_at": datetime.now(tz=UTC),
            }
            findings_db.append(finding_data)
            # Persist finding to DB
            try:
                db = SessionLocal()
                create_finding(db, finding_data)
                db.close()
            except Exception:
                logger.warning("DB persist failed for finding in scan %s", scan_id, exc_info=True)

        # Web scan simulation
        if ScanType.WEB in config.scan_types:
            if _is_cancelled():
                return
            scan["progress"] = 50
            await ws_manager.broadcast(
                scan_id, {"scan_id": scan_id, "status": "running", "progress": 50}
            )
            logger.info(f"Scan {scan_id}: Web scan in progress...")

            finding_data = {
                "id": secrets.token_urlsafe(16),
                "scan_id": scan_id,
                "title": "Missing Security Headers",
                "description": "X-Frame-Options and CSP headers are missing",
                "severity": "low",
                "cvss_score": 3.7,
                "category": "web",
                "recommendation": "Implement security headers in web server configuration",
                "detected_at": datetime.now(tz=UTC),
            }
            findings_db.append(finding_data)
            try:
                db = SessionLocal()
                create_finding(db, finding_data)
                db.close()
            except Exception:
                logger.warning("DB persist failed for finding in scan %s", scan_id, exc_info=True)

        # API scan simulation
        if ScanType.API in config.scan_types:
            if _is_cancelled():
                return
            scan["progress"] = 75
            await ws_manager.broadcast(
                scan_id, {"scan_id": scan_id, "status": "running", "progress": 75}
            )
            logger.info(f"Scan {scan_id}: API scan in progress...")

        # Complete scan
        if _is_cancelled():
            return
        scan["progress"] = 100
        scan["status"] = ScanStatus.COMPLETED
        scan["completed_at"] = datetime.now(tz=UTC)
        await ws_manager.broadcast(
            scan_id, {"scan_id": scan_id, "status": "completed", "progress": 100}
        )

        # Count findings + severity from DB (fallback to in-memory cache)
        try:
            db = SessionLocal()
            findings_count = count_findings(db, scan_id=scan_id)
            severity_breakdown = get_severity_breakdown(db, scan_id=scan_id)
            db.close()
        except Exception:
            logger.warning("DB count failed for scan %s", scan_id, exc_info=True)
            scan_findings = [f for f in findings_db if f["scan_id"] == scan_id]
            findings_count = len(scan_findings)
            severity_breakdown: dict[str, int] = {}
            for finding in scan_findings:
                sev = finding["severity"]
                severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
        scan["findings_count"] = findings_count
        scan["severity_breakdown"] = severity_breakdown

        # Persist final state to DB
        try:
            db = SessionLocal()
            db_update_scan(
                db,
                scan_id,
                {
                    "status": "completed",
                    "progress": 100,
                    "completed_at": scan["completed_at"],
                    "findings_count": findings_count,
                    "severity_breakdown": severity_breakdown,
                },
            )
            db.close()
        except Exception:
            logger.warning("DB persist failed for scan %s completion", scan_id, exc_info=True)

        if mongo_collection is not None:
            mongo_collection.update_one(
                {"scan_id": scan_id},
                {
                    "$set": {
                        "scan_id": scan_id,
                        "target": config.target,
                        "status": scan["status"],
                        "findings": [f for f in findings_db if f["scan_id"] == scan_id],
                        "severity_breakdown": severity_breakdown,
                        "updated_at": datetime.now(tz=UTC),
                    }
                },
                upsert=True,
            )

        logger.info(f"Scan {scan_id} completed successfully with {findings_count} findings")

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}")
        scan["status"] = ScanStatus.FAILED
        scan["completed_at"] = datetime.now(tz=UTC)

        try:
            db = SessionLocal()
            db_update_scan(db, scan_id, {"status": "failed", "completed_at": scan["completed_at"]})
            db.close()
        except Exception:
            logger.warning("DB persist failed for scan %s failure", scan_id, exc_info=True)

        await ws_manager.broadcast(
            scan_id, {"scan_id": scan_id, "status": "failed", "progress": scan.get("progress", 0)}
        )


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "scan", "timestamp": datetime.now(tz=UTC).isoformat()}


@app.get("/metrics")
async def metrics() -> PlainTextResponse:
    """Minimal Prometheus-compatible metrics endpoint."""
    body = (
        "# HELP cosmicsec_scan_service_up Scan service health status\n"
        "# TYPE cosmicsec_scan_service_up gauge\n"
        "cosmicsec_scan_service_up 1\n"
    )
    return PlainTextResponse(content=body, media_type="text/plain; version=0.0.4")


@app.post("/scans", response_model=Scan)
async def create_scan(config: ScanConfig, background_tasks: BackgroundTasks, request: Request):
    """Create and initiate a new security scan."""
    org_id = request.headers.get("X-Org-Id")
    workspace_id = request.headers.get("X-Workspace-Id")

    if org_id:
        quotas = await _fetch_org_quotas(org_id)
        max_scans = quotas.get("max_scans_per_day", 1000)
        # Try DB count first, fall back to in-memory
        try:
            db = SessionLocal()
            used = count_scans_today_for_org(db, org_id)
            db.close()
        except Exception:
            used = _scans_today_for_org(org_id)
        if used >= max_scans:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Scan quota exceeded for org {org_id} ({used}/{max_scans} today)",
            )

    scan_id = secrets.token_urlsafe(16)

    scan_data: dict[str, Any] = {
        "id": scan_id,
        "target": config.target,
        "scan_types": config.scan_types,
        "status": ScanStatus.PENDING,
        "created_at": datetime.now(tz=UTC),
        "org_id": org_id,
        "workspace_id": workspace_id,
        "started_at": None,
        "completed_at": None,
        "progress": 0,
        "findings_count": 0,
        "severity_breakdown": {},
    }

    scans_db[scan_id] = scan_data

    # Persist to database
    try:
        db = SessionLocal()
        db_create_scan(db, scan_data)
        db.close()
    except Exception:
        logger.warning("DB persist failed for new scan %s — in-memory only", scan_id, exc_info=True)

    # Start scan in background
    background_tasks.add_task(perform_scan, scan_id, config)

    logger.info(f"Created new scan {scan_id} for target {config.target} (org={org_id})")

    return Scan(**scan_data)


@app.post("/scans/{scan_id}/enqueue")
async def enqueue_scan(scan_id: str):
    """Queue scan execution using Celery when available."""
    scan = _load_scan_from_cache_or_db(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    if celery_app is None:
        return {"queued": False, "reason": "Celery not configured", "scan_id": scan_id}

    celery_app.send_task(
        "scan.perform",
        kwargs={"scan_id": scan_id, "target": scan["target"]},
    )
    return {"queued": True, "scan_id": scan_id}


@app.get("/scans/{scan_id}", response_model=Scan)
async def get_scan(scan_id: str):
    """Get scan details by ID — checks in-memory cache then database."""
    scan = _load_scan_from_cache_or_db(scan_id)
    if scan:
        return Scan(**scan)

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")


@app.get("/scans", response_model=list[Scan])
async def list_scans(status_filter: ScanStatus | None = None, limit: int = 10, offset: int = 0):
    """List all scans with optional filtering — DB with in-memory fallback."""
    # Try DB first
    try:
        db = SessionLocal()
        scans = db_list_scans(db, status_filter=status_filter, limit=limit, offset=offset)
        db.close()
        return [Scan(**scan) for scan in scans]
    except Exception:
        logger.warning("DB list scans failed — falling back to in-memory", exc_info=True)

    # Fallback to in-memory
    scans_list = list(scans_db.values())
    if status_filter:
        scans_list = [s for s in scans_list if s["status"] == status_filter]
    scans_list.sort(key=lambda x: x["created_at"], reverse=True)
    scans_list = scans_list[offset : offset + limit]
    return [Scan(**scan) for scan in scans_list]


@app.get("/scans/{scan_id}/findings", response_model=list[Finding])
async def get_scan_findings(scan_id: str):
    """Get all findings for a specific scan — DB with in-memory fallback."""
    # Try DB first
    try:
        db = SessionLocal()
        db_findings = list_findings_for_scan(db, scan_id)
        db.close()
        return [Finding(**f) for f in db_findings]
    except Exception:
        logger.warning("DB read findings failed for scan %s", scan_id, exc_info=True)

    # Check scan exists
    if scan_id not in scans_db:
        try:
            db = SessionLocal()
            scan = db_get_scan(db, scan_id)
            db.close()
            if not scan:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    scan_findings = [f for f in findings_db if f["scan_id"] == scan_id]
    return [Finding(**finding) for finding in scan_findings]


@app.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan and its findings from both DB and in-memory cache."""
    # Delete from DB
    db_deleted = False
    try:
        db = SessionLocal()
        db_deleted = db_delete_scan(db, scan_id)
        db.close()
    except Exception:
        logger.warning("DB delete failed for scan %s", scan_id, exc_info=True)

    in_memory_exists = scan_id in scans_db
    if not db_deleted and not in_memory_exists:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    # Delete from in-memory cache
    scans_db.pop(scan_id, None)

    global findings_db
    findings_db = [f for f in findings_db if f["scan_id"] != scan_id]

    logger.info(f"Deleted scan {scan_id}")

    return {"message": "Scan deleted successfully"}


@app.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancel an active scan and persist cancellation state."""
    scan = _load_scan_from_cache_or_db(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    current_status = str(scan.get("status", "")).lower()
    if current_status in {
        ScanStatus.COMPLETED.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    }:
        return {
            "scan_id": scan_id,
            "status": current_status,
            "cancelled": current_status == ScanStatus.CANCELLED.value,
            "message": "Scan is no longer cancellable",
        }

    scan["status"] = ScanStatus.CANCELLED
    scan["completed_at"] = datetime.now(tz=UTC)

    try:
        db = SessionLocal()
        db_update_scan(
            db,
            scan_id,
            {"status": ScanStatus.CANCELLED.value, "completed_at": scan["completed_at"]},
        )
        db.close()
    except Exception:
        logger.warning("DB persist failed for scan %s cancellation", scan_id, exc_info=True)

    await ws_manager.broadcast(
        scan_id,
        {
            "scan_id": scan_id,
            "status": ScanStatus.CANCELLED,
            "progress": scan.get("progress", 0),
        },
    )
    return {"scan_id": scan_id, "status": ScanStatus.CANCELLED, "cancelled": True}


@app.get("/stats")
async def get_stats():
    """Get scanning statistics — DB with in-memory fallback."""
    # Try DB first
    try:
        from services.common.models import ScanModel as _SM

        db = SessionLocal()
        total_scans = db.query(_SM).count()
        completed_scans = db.query(_SM).filter(_SM.status == "completed").count()
        running_scans = db.query(_SM).filter(_SM.status == "running").count()
        total_findings_count = count_findings(db)
        breakdown = get_severity_breakdown(db)
        db.close()
        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "running_scans": running_scans,
            "total_findings": total_findings_count,
            "severity_breakdown": breakdown,
            "timestamp": datetime.now(tz=UTC).isoformat(),
        }
    except Exception:
        logger.warning("DB stats query failed — falling back to in-memory", exc_info=True)

    # In-memory fallback
    total_scans = len(scans_db)
    completed_scans = sum(1 for s in scans_db.values() if s["status"] == ScanStatus.COMPLETED)
    running_scans = sum(1 for s in scans_db.values() if s["status"] == ScanStatus.RUNNING)
    total_findings = len(findings_db)

    severity_breakdown: dict[str, int] = {}
    for finding in findings_db:
        severity = finding["severity"]
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1

    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "running_scans": running_scans,
        "total_findings": total_findings,
        "severity_breakdown": severity_breakdown,
        "timestamp": datetime.now(tz=UTC).isoformat(),
    }


@app.get("/stats/dashboard")
async def get_dashboard_stats():
    """Return materialized dashboard stats when available."""
    db = SessionLocal()
    try:
        row = db.execute(text("SELECT * FROM dashboard_stats LIMIT 1")).mappings().first()
        if row:
            return dict(row)
    except Exception:
        logger.warning("dashboard_stats materialized view unavailable", exc_info=True)
    finally:
        db.close()
    return await get_stats()


@app.post("/stats/dashboard/refresh")
async def refresh_dashboard_stats():
    """Force-refresh dashboard materialized view."""
    ok = _refresh_dashboard_stats_view()
    if not ok:
        raise HTTPException(status_code=503, detail="dashboard_stats refresh failed")
    return {"ok": True, "refreshed_at": datetime.now(tz=UTC).isoformat()}


class QuotaUpdateRequest(BaseModel):
    max_scans_per_day: int = Field(default=1000, ge=1, le=100000)
    max_workspaces: int | None = Field(default=None, ge=1)
    max_users: int | None = Field(default=None, ge=1)


@app.post("/findings/import")
async def import_findings_batch(request: Request):
    """Import external/offline findings payload into persistent store."""
    raw = await request.body()
    if request.headers.get("content-encoding", "").lower() == "gzip":
        try:
            raw = gzip.decompress(raw)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Invalid gzip payload: {exc}") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {exc}") from exc

    findings = payload.get("findings", []) if isinstance(payload, dict) else payload
    if not isinstance(findings, list):
        raise HTTPException(status_code=400, detail="findings payload must be a list")

    db = SessionLocal()
    imported = 0
    scan_id = (
        str(payload.get("scan_id", f"offline-import-{secrets.token_hex(4)}"))
        if isinstance(payload, dict)
        else f"offline-import-{secrets.token_hex(4)}"
    )
    target = (
        str(payload.get("target", "offline-sync")) if isinstance(payload, dict) else "offline-sync"
    )
    try:
        existing = db_get_scan(db, scan_id)
        if not existing:
            db_create_scan(
                db,
                {
                    "id": scan_id,
                    "target": target,
                    "scan_types": ["web"],
                    "status": "completed",
                    "source": "offline_sync",
                },
            )
        for item in findings:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title", "")).strip()
            if not title:
                continue
            create_finding(
                db,
                {
                    "id": item.get("id"),
                    "scan_id": item.get("scan_id") or scan_id,
                    "title": title,
                    "severity": str(item.get("severity", "info")),
                    "description": item.get("description"),
                    "evidence": item.get("evidence"),
                    "tool": item.get("tool"),
                    "category": item.get("category"),
                    "target": item.get("target") or target,
                    "cve_id": item.get("cve_id"),
                    "cvss_score": item.get("cvss_score"),
                    "recommendation": item.get("recommendation", ""),
                    "source": "offline_sync",
                },
            )
            imported += 1
    finally:
        db.close()

    return {"imported": imported, "scan_id": scan_id}


@app.get("/findings")
async def list_findings(
    severity: str | None = None,
    scan_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """List findings with optional severity/scan filters and pagination."""
    try:
        db = SessionLocal()
        query = db.query(FindingModel)
        if severity:
            query = query.filter(FindingModel.severity == severity)
        if scan_id:
            query = query.filter(FindingModel.scan_id == scan_id)
        total = query.count()
        rows = query.order_by(FindingModel.created_at.desc()).offset(offset).limit(limit).all()
        db.close()
        items = [
            {
                "id": r.id,
                "scan_id": r.scan_id,
                "title": r.title,
                "severity": r.severity,
                "description": r.description,
                "tool": r.tool,
                "target": r.target,
                "cve_id": r.cve_id,
                "cvss_score": r.cvss_score,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
        return {
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
            "filters": {"severity": severity, "scan_id": scan_id},
        }
    except Exception:
        logger.warning("DB list findings failed", exc_info=True)
        # Graceful fallback from in-memory cache for dev/test resilience
        rows = findings_db
        if severity:
            rows = [r for r in rows if str(r.get("severity", "")).lower() == severity.lower()]
        if scan_id:
            rows = [r for r in rows if r.get("scan_id") == scan_id]
        total = len(rows)
        sliced = rows[offset : offset + limit]
        return {
            "items": sliced,
            "total": total,
            "limit": limit,
            "offset": offset,
            "filters": {"severity": severity, "scan_id": scan_id},
        }


@app.get("/findings/trending")
async def findings_trending(days: int = 7) -> dict[str, Any]:
    """Return daily severity trend for the latest N days."""
    window_days = max(1, min(days, 90))
    cutoff = datetime.now(tz=UTC) - timedelta(days=window_days)
    series: dict[str, dict[str, int]] = {}

    try:
        db = SessionLocal()
        rows = db.query(FindingModel).filter(FindingModel.created_at >= cutoff).all()
        db.close()
        for row in rows:
            if not row.created_at:
                continue
            day_key = row.created_at.date().isoformat()
            sev = str(row.severity or "info").lower()
            day_bucket = series.setdefault(day_key, {})
            day_bucket[sev] = day_bucket.get(sev, 0) + 1
    except Exception:
        logger.warning("DB trending query failed", exc_info=True)
        for item in findings_db:
            detected = item.get("detected_at")
            if isinstance(detected, datetime):
                if detected < cutoff:
                    continue
                day_key = detected.date().isoformat()
            else:
                day_key = datetime.now(tz=UTC).date().isoformat()
            sev = str(item.get("severity", "info")).lower()
            day_bucket = series.setdefault(day_key, {})
            day_bucket[sev] = day_bucket.get(sev, 0) + 1

    ordered_days = sorted(series.keys())
    return {
        "days": window_days,
        "series": [{"date": d, "severity_breakdown": series[d]} for d in ordered_days],
    }


@app.get("/orgs/{org_id}/quotas")
async def get_org_quotas(org_id: str):
    """Return quota configuration for an organization."""
    quotas = await _fetch_org_quotas(org_id)
    return {"org_id": org_id, "quotas": quotas}


@app.post("/orgs/{org_id}/quotas")
async def set_org_quotas(org_id: str, payload: QuotaUpdateRequest):
    """Update quotas for an organization (local override)."""
    current = tenant_quotas.setdefault(org_id, {})
    current["max_scans_per_day"] = payload.max_scans_per_day
    if payload.max_workspaces is not None:
        current["max_workspaces"] = payload.max_workspaces
    if payload.max_users is not None:
        current["max_users"] = payload.max_users
    return {"org_id": org_id, "quotas": current}


@app.websocket("/ws/scans/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    token = (
        websocket.query_params.get("token")
        or websocket.headers.get("authorization", "").removeprefix("Bearer ").strip()
    )
    if _validate_ws_token(token) is None:
        await websocket.close(code=4001)
        return
    await ws_manager.connect(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(scan_id, websocket)


# ===========================================================================
# Active Phase 2 endpoints (top-level)
# ===========================================================================


class ScheduleMonitorRequest(BaseModel):
    target: str = Field(..., description="Target URL, IP, or domain to monitor")
    scan_types: list[ScanType] = Field(
        default=[ScanType.WEB], description="Scan types to run on each cycle"
    )
    interval_seconds: int = Field(
        default=3600, ge=60, description="Seconds between scan runs (min 60)"
    )
    created_by: str = Field(default="api", description="Requesting user identifier")
    alert_on_new_critical: bool = Field(
        default=True, description="Emit alert when new critical findings appear"
    )


class FuzzRequest(BaseModel):
    base_url: str = Field(..., description="API base URL to fuzz")
    openapi_spec: dict[str, Any] | None = Field(
        default=None, description="Optional OpenAPI 3.x spec dict"
    )
    attack_types: list[str] | None = Field(
        default=None,
        description="Attack categories: sqli, xss, path_traversal, cmd_injection, ssrf, ssti, auth_bypass",
    )
    max_requests: int = Field(
        default=150, ge=10, le=500, description="Maximum HTTP requests to send"
    )
    timeout: int = Field(default=8, ge=2, le=30, description="Per-request timeout seconds")
    use_proxy_pool: bool = False
    proxy_url: str | None = None
    rotate_identity: bool = False
    client_profile: str | None = None
    use_tor: bool = False
    tor_mode: str | None = None


class ContainerScanRequest(BaseModel):
    artifact_type: str = Field(..., description="Type of artifact: 'dockerfile' or 'kubernetes'")
    content: str = Field(
        ..., description="Raw text content of the Dockerfile or Kubernetes YAML manifest"
    )


class SmartScanRequest(BaseModel):
    url: str = Field(..., description="Target URL to fingerprint and plan")
    previously_run: list[str] | None = Field(
        default=None, description="Scan types already executed"
    )
    use_proxy_pool: bool = False
    proxy_url: str | None = None
    rotate_identity: bool = False
    client_profile: str | None = None
    use_tor: bool = False
    tor_mode: str | None = None


class CloudScanRequest(BaseModel):
    provider: str = Field(..., description="Cloud provider: aws | azure | gcp | k8s")
    region: str | None = Field(default=None, description="Target region / cluster")
    resource_types: list[str] | None = Field(default=None, description="Resource types to scan")
    credentials_hint: str | None = Field(
        default=None, description="Credential profile name (no secrets)"
    )


class RegisterNodeRequest(BaseModel):
    node_id: str
    region: str
    capacity: int = Field(default=4, ge=1, le=128)
    tags: list[str] = Field(default_factory=list)


class NodeHeartbeatRequest(BaseModel):
    healthy: bool = True
    active_jobs: int | None = Field(default=None, ge=0)


class DistributedAssignRequest(BaseModel):
    target: str
    replicas: int = Field(default=1, ge=1, le=10)
    region_hint: str | None = None
    required_tags: list[str] = Field(default_factory=list)


_CLOUD_FINDINGS: dict[str, list[dict[str, Any]]] = {
    "aws": [
        {
            "title": "S3 bucket with public ACL",
            "severity": "critical",
            "category": "cloud",
            "description": "One or more S3 buckets allow unauthenticated public access.",
            "recommendation": "Enable S3 Block Public Access at account level.",
        },
        {
            "title": "IAM wildcard policy attached",
            "severity": "high",
            "category": "cloud",
            "description": "IAM policy contains Action:* or Resource:* granting over-privilege.",
            "recommendation": "Replace wildcards with least-privilege policy statements.",
        },
    ],
    "azure": [
        {
            "title": "Azure AD legacy authentication enabled",
            "severity": "high",
            "category": "cloud",
            "description": "Legacy authentication protocols can bypass MFA policies.",
            "recommendation": "Block legacy auth via Conditional Access.",
        },
        {
            "title": "Storage account allows HTTP traffic",
            "severity": "medium",
            "category": "cloud",
            "description": "Storage account accepts unencrypted HTTP connections.",
            "recommendation": "Enforce HTTPS-only in storage account settings.",
        },
    ],
    "gcp": [
        {
            "title": "GCS bucket with allUsers permission",
            "severity": "critical",
            "category": "cloud",
            "description": "GCS bucket grants allUsers public access.",
            "recommendation": "Remove allUsers bindings and enable uniform bucket-level access.",
        },
    ],
    "k8s": [
        {
            "title": "Kubernetes API server publicly accessible",
            "severity": "critical",
            "category": "cloud",
            "description": "K8s API endpoint is reachable from internet.",
            "recommendation": "Restrict API access to private networks and trusted IPs.",
        },
    ],
}


@app.post("/monitor/schedule", status_code=201)
async def schedule_monitoring(payload: ScheduleMonitorRequest) -> dict:
    job_id = await _monitor.schedule(
        target=payload.target,
        scan_types=[t.value for t in payload.scan_types],
        interval_seconds=payload.interval_seconds,
        created_by=payload.created_by,
        alert_on_new_critical=payload.alert_on_new_critical,
    )
    return {"job_id": job_id, "status": "scheduled", "target": payload.target}


@app.get("/monitor/jobs")
async def list_monitor_jobs() -> dict:
    return {"jobs": _monitor.list_jobs(), "active_count": _monitor.active_job_count}


@app.get("/monitor/jobs/{job_id}")
async def get_monitor_job(job_id: str) -> dict:
    job = _monitor.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Monitor job not found")
    return job


@app.post("/monitor/jobs/{job_id}/pause")
async def pause_monitor_job(job_id: str) -> dict:
    if not _monitor.pause(job_id):
        raise HTTPException(status_code=404, detail="Monitor job not found")
    return {"job_id": job_id, "status": "paused"}


@app.post("/monitor/jobs/{job_id}/resume")
async def resume_monitor_job(job_id: str) -> dict:
    if not _monitor.resume(job_id):
        raise HTTPException(status_code=404, detail="Monitor job not found")
    return {"job_id": job_id, "status": "active"}


@app.delete("/monitor/jobs/{job_id}")
async def cancel_monitor_job(job_id: str) -> dict:
    if not _monitor.cancel(job_id):
        raise HTTPException(status_code=404, detail="Monitor job not found")
    return {"job_id": job_id, "status": "cancelled"}


@app.post("/scans/fuzz")
async def fuzz_api(payload: FuzzRequest) -> dict:
    egress_options = _egress_options_from_payload(payload.model_dump())
    fuzzer = APIFuzzer(
        timeout=payload.timeout,
        max_requests=payload.max_requests,
        egress_options=egress_options,
    )
    return await fuzzer.fuzz(
        base_url=payload.base_url,
        openapi_spec=payload.openapi_spec,
        attack_types=payload.attack_types,
    )


@app.post("/scans/container")
async def scan_container(payload: ContainerScanRequest) -> dict:
    return scan_container_artifact(payload.artifact_type, payload.content)


@app.post("/scans/smart-plan")
async def smart_scan_plan(payload: SmartScanRequest) -> dict:
    egress_options = _egress_options_from_payload(payload.model_dump())
    return await smart_scan(
        payload.url,
        previously_run=payload.previously_run,
        egress_options=egress_options,
    )


@app.post("/scans/cloud")
async def cloud_scan(payload: CloudScanRequest) -> dict:
    provider = payload.provider.lower()
    findings = _CLOUD_FINDINGS.get(provider, [])
    stamped = []
    for f in findings:
        item = dict(f)
        item["id"] = secrets.token_urlsafe(8)
        item["detected_at"] = datetime.now(tz=UTC).isoformat()
        stamped.append(item)

    severity_breakdown: dict[str, int] = {}
    for f in stamped:
        s = f.get("severity", "info")
        severity_breakdown[s] = severity_breakdown.get(s, 0) + 1

    return {
        "provider": provider,
        "region": payload.region,
        "findings": stamped,
        "findings_count": len(stamped),
        "severity_breakdown": severity_breakdown,
        "timestamp": datetime.now(tz=UTC).isoformat(),
    }


@app.post("/distributed/nodes/register", status_code=201)
async def register_node(payload: RegisterNodeRequest) -> dict:
    node = _distributed.register_node(
        node_id=payload.node_id,
        region=payload.region,
        capacity=payload.capacity,
        tags=payload.tags,
    )
    return {"status": "registered", "node": node}


@app.get("/distributed/nodes")
async def list_nodes() -> dict:
    return {"nodes": _distributed.list_nodes(), "total": len(_distributed.list_nodes())}


@app.post("/distributed/nodes/{node_id}/heartbeat")
async def node_heartbeat(node_id: str, payload: NodeHeartbeatRequest) -> dict:
    node = _distributed.heartbeat(node_id, healthy=payload.healthy, active_jobs=payload.active_jobs)
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    return {"status": "updated", "node": node}


@app.post("/distributed/assign")
async def distributed_assign(payload: DistributedAssignRequest) -> dict:
    return _distributed.assign_target(
        target=payload.target,
        replicas=payload.replicas,
        region_hint=payload.region_hint,
        required_tags=payload.required_tags,
    )


@app.post("/distributed/nodes/{node_id}/complete")
async def distributed_complete(node_id: str) -> dict:
    ok = _distributed.complete_assignment(node_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Node not found")
    return {"status": "completed", "node_id": node_id}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.getenv("COSMICSEC_BIND_HOST", "127.0.0.1"), port=8002)
