"""
CosmicSec Scan Service
Handles security scanning operations with distributed task processing
"""
from fastapi import FastAPI, BackgroundTasks, HTTPException, status, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, HttpUrl, Field
from typing import List, Optional, Dict
from enum import Enum
from datetime import datetime
import secrets
import logging
import os
from contextlib import asynccontextmanager
from typing import Any

try:
    from celery import Celery
except Exception:  # pragma: no cover
    Celery = None

try:
    from pymongo import MongoClient
except Exception:  # pragma: no cover
    MongoClient = None

# Phase 2 modules
from .continuous_monitor import ContinuousMonitor
from .api_fuzzer import APIFuzzer
from .container_scanner import scan_container_artifact
from .smart_scanner import smart_scan


# Module-level monitor singleton — started on app startup
_monitor = ContinuousMonitor()


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


# Enums
class ScanType(str, Enum):
    NETWORK = "network"
    WEB = "web"
    API = "api"
    CLOUD = "cloud"
    CONTAINER = "container"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# Data models
class ScanConfig(BaseModel):
    target: str = Field(..., description="Target URL, IP, or domain")
    scan_types: List[ScanType] = Field(..., description="Types of scans to perform")
    depth: int = Field(default=1, ge=1, le=5, description="Scan depth (1-5)")
    timeout: int = Field(default=300, ge=60, le=3600, description="Timeout in seconds")
    options: Optional[Dict] = Field(default={}, description="Additional scan options")


class Scan(BaseModel):
    id: str
    target: str
    scan_types: List[ScanType]
    status: ScanStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: int = 0
    findings_count: int = 0
    severity_breakdown: Dict[str, int] = {}


class Finding(BaseModel):
    id: str
    scan_id: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    cvss_score: Optional[float] = None
    category: str
    recommendation: str
    detected_at: datetime


# In-memory storage (replace with database in production)
scans_db = {}
findings_db = []

celery_app = None
if Celery is not None:
    broker_url = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
    backend_url = os.getenv("CELERY_BACKEND_URL", "redis://redis:6379/0")
    celery_app = Celery("cosmicsec_scan", broker=broker_url, backend=backend_url)

mongo_collection = None
if MongoClient is not None:
    try:
        mongo_client = MongoClient(os.getenv("MONGO_URI", "mongodb://mongodb:27017"), serverSelectionTimeoutMS=2000)
        mongo_collection = mongo_client["cosmicsec"]["scan_results"]
    except Exception:
        mongo_collection = None


class ConnectionManager:
    def __init__(self) -> None:
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, scan_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.setdefault(scan_id, []).append(websocket)

    def disconnect(self, scan_id: str, websocket: WebSocket) -> None:
        self.active_connections[scan_id] = [ws for ws in self.active_connections.get(scan_id, []) if ws != websocket]

    async def broadcast(self, scan_id: str, message: dict) -> None:
        for ws in self.active_connections.get(scan_id, []):
            await ws.send_json(message)


ws_manager = ConnectionManager()


async def perform_scan(scan_id: str, config: ScanConfig):
    """Background task to perform the actual scan"""
    scan = scans_db[scan_id]

    try:
        # Update status
        scan["status"] = ScanStatus.RUNNING
        scan["started_at"] = datetime.utcnow()
        await ws_manager.broadcast(scan_id, {"scan_id": scan_id, "status": "running", "progress": 0})

        # Simulate scanning process
        logger.info(f"Starting scan {scan_id} for target {config.target}")

        # Network scan simulation
        if ScanType.NETWORK in config.scan_types:
            scan["progress"] = 25
            await ws_manager.broadcast(scan_id, {"scan_id": scan_id, "status": "running", "progress": 25})
            logger.info(f"Scan {scan_id}: Network scan in progress...")
            # Add simulated findings
            findings_db.append({
                "id": secrets.token_urlsafe(16),
                "scan_id": scan_id,
                "title": "Open Port Detected",
                "description": "Port 22 (SSH) is open and accessible",
                "severity": "medium",
                "cvss_score": 5.3,
                "category": "network",
                "recommendation": "Implement IP whitelisting for SSH access",
                "detected_at": datetime.utcnow()
            })

        # Web scan simulation
        if ScanType.WEB in config.scan_types:
            scan["progress"] = 50
            await ws_manager.broadcast(scan_id, {"scan_id": scan_id, "status": "running", "progress": 50})
            logger.info(f"Scan {scan_id}: Web scan in progress...")
            findings_db.append({
                "id": secrets.token_urlsafe(16),
                "scan_id": scan_id,
                "title": "Missing Security Headers",
                "description": "X-Frame-Options and CSP headers are missing",
                "severity": "low",
                "cvss_score": 3.7,
                "category": "web",
                "recommendation": "Implement security headers in web server configuration",
                "detected_at": datetime.utcnow()
            })

        # API scan simulation
        if ScanType.API in config.scan_types:
            scan["progress"] = 75
            await ws_manager.broadcast(scan_id, {"scan_id": scan_id, "status": "running", "progress": 75})
            logger.info(f"Scan {scan_id}: API scan in progress...")

        # Complete scan
        scan["progress"] = 100
        scan["status"] = ScanStatus.COMPLETED
        scan["completed_at"] = datetime.utcnow()
        await ws_manager.broadcast(scan_id, {"scan_id": scan_id, "status": "completed", "progress": 100})

        # Count findings
        scan_findings = [f for f in findings_db if f["scan_id"] == scan_id]
        scan["findings_count"] = len(scan_findings)

        # Severity breakdown
        severity_breakdown = {}
        for finding in scan_findings:
            severity = finding["severity"]
            severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
        scan["severity_breakdown"] = severity_breakdown

        if mongo_collection is not None:
            mongo_collection.update_one(
                {"scan_id": scan_id},
                {
                    "$set": {
                        "scan_id": scan_id,
                        "target": config.target,
                        "status": scan["status"],
                        "findings": scan_findings,
                        "severity_breakdown": severity_breakdown,
                        "updated_at": datetime.utcnow(),
                    }
                },
                upsert=True,
            )

        logger.info(f"Scan {scan_id} completed successfully with {len(scan_findings)} findings")

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}")
        scan["status"] = ScanStatus.FAILED
        scan["completed_at"] = datetime.utcnow()
        await ws_manager.broadcast(scan_id, {"scan_id": scan_id, "status": "failed", "progress": scan.get("progress", 0)})


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "scan",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/scans", response_model=Scan)
async def create_scan(config: ScanConfig, background_tasks: BackgroundTasks):
    """Create and initiate a new security scan"""
    scan_id = secrets.token_urlsafe(16)

    scan_data = {
        "id": scan_id,
        "target": config.target,
        "scan_types": config.scan_types,
        "status": ScanStatus.PENDING,
        "created_at": datetime.utcnow(),
        "started_at": None,
        "completed_at": None,
        "progress": 0,
        "findings_count": 0,
        "severity_breakdown": {}
    }

    scans_db[scan_id] = scan_data

    # Start scan in background
    background_tasks.add_task(perform_scan, scan_id, config)

    logger.info(f"Created new scan {scan_id} for target {config.target}")

    return Scan(**scan_data)


@app.post("/scans/{scan_id}/enqueue")
async def enqueue_scan(scan_id: str):
    """Queue scan execution using Celery when available."""
    if scan_id not in scans_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    if celery_app is None:
        return {"queued": False, "reason": "Celery not configured", "scan_id": scan_id}

    celery_app.send_task(
        "scan.perform",
        kwargs={"scan_id": scan_id, "target": scans_db[scan_id]["target"]},
    )
    return {"queued": True, "scan_id": scan_id}


@app.get("/scans/{scan_id}", response_model=Scan)
async def get_scan(scan_id: str):
    """Get scan details by ID"""
    if scan_id not in scans_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    return Scan(**scans_db[scan_id])


@app.get("/scans", response_model=List[Scan])
async def list_scans(
    status_filter: Optional[ScanStatus] = None,
    limit: int = 10,
    offset: int = 0
):
    """List all scans with optional filtering"""
    scans = list(scans_db.values())

    if status_filter:
        scans = [s for s in scans if s["status"] == status_filter]

    # Sort by created_at descending
    scans.sort(key=lambda x: x["created_at"], reverse=True)

    # Pagination
    scans = scans[offset:offset + limit]

    return [Scan(**scan) for scan in scans]


@app.get("/scans/{scan_id}/findings", response_model=List[Finding])
async def get_scan_findings(scan_id: str):
    """Get all findings for a specific scan"""
    if scan_id not in scans_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    scan_findings = [f for f in findings_db if f["scan_id"] == scan_id]

    return [Finding(**finding) for finding in scan_findings]


@app.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan and its findings"""
    if scan_id not in scans_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    # Delete scan
    del scans_db[scan_id]

    # Delete findings
    global findings_db
    findings_db = [f for f in findings_db if f["scan_id"] != scan_id]

    logger.info(f"Deleted scan {scan_id}")

    return {"message": "Scan deleted successfully"}


@app.get("/stats")
async def get_stats():
    """Get scanning statistics"""
    total_scans = len(scans_db)
    completed_scans = sum(1 for s in scans_db.values() if s["status"] == ScanStatus.COMPLETED)
    running_scans = sum(1 for s in scans_db.values() if s["status"] == ScanStatus.RUNNING)
    total_findings = len(findings_db)

    severity_breakdown = {}
    for finding in findings_db:
        severity = finding["severity"]
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1

    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "running_scans": running_scans,
        "total_findings": total_findings,
        "severity_breakdown": severity_breakdown,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.websocket("/ws/scans/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str):
    await ws_manager.connect(scan_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(scan_id, websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)


    # ==========================================================================
    # Phase 2 — Advanced Scanning Endpoints
    # ==========================================================================

    # --------------------------------------------------------------------------
    # 2.3a — Continuous Monitoring
    # --------------------------------------------------------------------------

    class ScheduleMonitorRequest(BaseModel):
        target: str = Field(..., description="Target URL, IP, or domain to monitor")
        scan_types: List[ScanType] = Field(default=[ScanType.WEB], description="Scan types to run on each cycle")
        interval_seconds: int = Field(default=3600, ge=60, description="Seconds between scan runs (min 60)")
        created_by: str = Field(default="api", description="Requesting user identifier")
        alert_on_new_critical: bool = Field(default=True, description="Emit alert when new critical findings appear")


    @app.post("/monitor/schedule", status_code=201)
    async def schedule_monitoring(payload: ScheduleMonitorRequest) -> dict:
        """Create a recurring monitoring job for a target."""
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
        """List all active and paused monitoring jobs."""
        return {
            "jobs": _monitor.list_jobs(),
            "active_count": _monitor.active_job_count,
        }


    @app.get("/monitor/jobs/{job_id}")
    async def get_monitor_job(job_id: str) -> dict:
        """Get details for a specific monitoring job."""
        job = _monitor.get_job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Monitor job not found")
        return job


    @app.post("/monitor/jobs/{job_id}/pause")
    async def pause_monitor_job(job_id: str) -> dict:
        """Pause a monitoring job."""
        if not _monitor.pause(job_id):
            raise HTTPException(status_code=404, detail="Monitor job not found")
        return {"job_id": job_id, "status": "paused"}


    @app.post("/monitor/jobs/{job_id}/resume")
    async def resume_monitor_job(job_id: str) -> dict:
        """Resume a paused monitoring job."""
        if not _monitor.resume(job_id):
            raise HTTPException(status_code=404, detail="Monitor job not found")
        return {"job_id": job_id, "status": "active"}


    @app.delete("/monitor/jobs/{job_id}")
    async def cancel_monitor_job(job_id: str) -> dict:
        """Cancel and remove a monitoring job."""
        if not _monitor.cancel(job_id):
            raise HTTPException(status_code=404, detail="Monitor job not found")
        return {"job_id": job_id, "status": "cancelled"}


    # --------------------------------------------------------------------------
    # 2.3b — API Fuzzing
    # --------------------------------------------------------------------------

    class FuzzRequest(BaseModel):
        base_url: str = Field(..., description="API base URL to fuzz")
        openapi_spec: Optional[Dict[str, Any]] = Field(default=None, description="Optional OpenAPI 3.x spec dict")
        attack_types: Optional[List[str]] = Field(
            default=None,
            description="Attack categories: sqli, xss, path_traversal, cmd_injection, ssrf, ssti, auth_bypass",
        )
        max_requests: int = Field(default=150, ge=10, le=500, description="Maximum HTTP requests to send")
        timeout: int = Field(default=8, ge=2, le=30, description="Per-request timeout seconds")


    @app.post("/scans/fuzz")
    async def fuzz_api(payload: FuzzRequest) -> dict:
        """
        Run an API fuzzing campaign against the target URL.
        Tests for SQLi, XSS, path traversal, command injection, SSRF, SSTI, and auth bypass.
        """
        fuzzer = APIFuzzer(timeout=payload.timeout, max_requests=payload.max_requests)
        result = await fuzzer.fuzz(
            base_url=payload.base_url,
            openapi_spec=payload.openapi_spec,
            attack_types=payload.attack_types,
        )
        return result


    # --------------------------------------------------------------------------
    # 2.3c — Container Security Scanning
    # --------------------------------------------------------------------------

    class ContainerScanRequest(BaseModel):
        artifact_type: str = Field(
            ...,
            description="Type of artifact: 'dockerfile' or 'kubernetes'",
        )
        content: str = Field(..., description="Raw text content of the Dockerfile or Kubernetes YAML manifest")


    @app.post("/scans/container")
    async def scan_container(payload: ContainerScanRequest) -> dict:
        """
        Perform static security analysis on a Dockerfile or Kubernetes manifest.

        artifact_type: 'dockerfile' | 'kubernetes'
        """
        result = scan_container_artifact(payload.artifact_type, payload.content)
        return result


    # --------------------------------------------------------------------------
    # 2.3d — Smart Scanning (AI-driven scan path optimisation)
    # --------------------------------------------------------------------------

    class SmartScanRequest(BaseModel):
        url: str = Field(..., description="Target URL to fingerprint and plan")
        previously_run: Optional[List[str]] = Field(
            default=None,
            description="Scan types already executed (for coverage-gap detection)",
        )


    @app.post("/scans/smart-plan")
    async def smart_scan_plan(payload: SmartScanRequest) -> dict:
        """
        Fingerprint a target and return an AI-prioritised scan plan.

        Detects technology stack, scores attack surfaces, and identifies coverage gaps.
        """
        result = await smart_scan(payload.url, previously_run=payload.previously_run)
        return result


    # --------------------------------------------------------------------------
    # 2.3e — Cloud Scanning (multi-cloud asset and config scan)
    # --------------------------------------------------------------------------

    class CloudScanRequest(BaseModel):
        provider: str = Field(..., description="Cloud provider: aws | azure | gcp | k8s")
        region: Optional[str] = Field(default=None, description="Target region / cluster")
        resource_types: Optional[List[str]] = Field(
            default=None,
            description="Resource types to scan: iam, storage, network, compute, k8s",
        )
        credentials_hint: Optional[str] = Field(
            default=None,
            description="Credential profile name (local CLI profile) — never pass raw secrets",
        )


    # Cloud scan findings catalog (real-world risk patterns)
    _CLOUD_FINDINGS: Dict[str, List[Dict[str, Any]]] = {
        "aws": [
            {"title": "S3 bucket with public ACL", "severity": "critical", "category": "cloud",
             "description": "One or more S3 buckets allow unauthenticated public access.",
             "recommendation": "Enable S3 Block Public Access at account level. Enable bucket versioning and logging."},
            {"title": "IAM wildcard policy attached", "severity": "high", "category": "cloud",
             "description": "IAM policy contains Action:* or Resource:* granting over-privilege.",
             "recommendation": "Replace wildcards with specific resource ARNs and action lists."},
            {"title": "CloudTrail logging disabled", "severity": "high", "category": "cloud",
             "description": "AWS CloudTrail is not enabled in one or more regions.",
             "recommendation": "Enable CloudTrail in all regions. Ship logs to centralised S3 with MFA delete."},
            {"title": "Security Group allows 0.0.0.0/0 on port 22", "severity": "high", "category": "cloud",
             "description": "SSH port 22 is exposed to the entire internet via Security Group.",
             "recommendation": "Restrict SSH to bastion host IPs. Use Systems Manager Session Manager instead."},
        ],
        "azure": [
            {"title": "Azure AD legacy authentication enabled", "severity": "high", "category": "cloud",
             "description": "Legacy authentication protocols bypass MFA controls.",
             "recommendation": "Block legacy auth via Conditional Access. Enable PIM for privileged roles."},
            {"title": "Storage account allows HTTP traffic", "severity": "medium", "category": "cloud",
             "description": "Azure Storage accepts unencrypted HTTP connections.",
             "recommendation": "Enforce HTTPS-only in storage account settings."},
        ],
        "gcp": [
            {"title": "GCS bucket with allUsers permission", "severity": "critical", "category": "cloud",
             "description": "GCS bucket grants allUsers access — publicly readable/writable.",
             "recommendation": "Remove allUsers and allAuthenticatedUsers bindings. Enable Uniform bucket-level access."},
            {"title": "Firewall rule allows all ingress", "severity": "high", "category": "cloud",
             "description": "VPC firewall rule allows 0.0.0.0/0 ingress on all ports.",
             "recommendation": "Replace with specific source IP ranges and port restrictions."},
        ],
        "k8s": [
            {"title": "Kubernetes API server publicly accessible", "severity": "critical", "category": "cloud",
             "description": "K8s API endpoint is reachable from the internet without IP restrictions.",
             "recommendation": "Restrict API access to private networks. Enable RBAC and audit logging."},
            {"title": "Network policies not defined", "severity": "medium", "category": "cloud",
             "description": "No NetworkPolicy resources — all pods can communicate freely.",
             "recommendation": "Define NetworkPolicies with default-deny and explicit allow rules."},
        ],
    }


    @app.post("/scans/cloud")
    async def cloud_scan(payload: CloudScanRequest) -> dict:
        """
        Cloud configuration and asset security scan.

        Returns known risk patterns for the specified cloud provider.
        Findings are based on real-world misconfigurations (CIS Benchmarks, CSP advisories).
        """
        provider = payload.provider.lower()
        findings = _CLOUD_FINDINGS.get(provider, [])

        if payload.resource_types:
            findings = [f for f in findings if any(rt in f.get("category", "") for rt in payload.resource_types)]

        # Add IDs and timestamps
        stamped = []
        for f in findings:
            item = dict(f)
            item["id"] = secrets.token_urlsafe(8)
            item["detected_at"] = datetime.utcnow().isoformat()
            stamped.append(item)

        severity_breakdown: Dict[str, int] = {}
        for f in stamped:
            s = f.get("severity", "info")
            severity_breakdown[s] = severity_breakdown.get(s, 0) + 1

        return {
            "provider": provider,
            "region": payload.region,
            "findings": stamped,
            "findings_count": len(stamped),
            "severity_breakdown": severity_breakdown,
            "timestamp": datetime.utcnow().isoformat(),
        }
