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

try:
    from celery import Celery
except Exception:  # pragma: no cover
    Celery = None

try:
    from pymongo import MongoClient
except Exception:  # pragma: no cover
    MongoClient = None

app = FastAPI(
    title="CosmicSec Scan Service",
    description="Security scanning service with Helix AI analysis",
    version="1.0.0"
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
