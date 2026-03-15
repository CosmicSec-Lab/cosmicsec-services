"""
CosmicSec API Gateway
Main entry point for all API requests with routing, authentication, and rate limiting
"""
from fastapi import FastAPI, Request, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import httpx
import time
import asyncio
from typing import Optional
import logging

# Initialize FastAPI app
app = FastAPI(
    title="CosmicSec API Gateway",
    description="GuardAxisSphere Platform - Universal Cybersecurity Intelligence Platform powered by Helix AI",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure this properly in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    logger.info(f"{request.method} {request.url.path} - {response.status_code} - {process_time:.3f}s")
    return response

# Service URLs (configure via environment variables in production)
SERVICE_URLS = {
    "auth": "http://auth-service:8001",
    "scan": "http://scan-service:8002",
    "ai": "http://ai-service:8003",
    "recon": "http://recon-service:8004",
    "report": "http://report-service:8005",
    "collab": "http://collab-service:8006",
    "plugins": "http://plugin-registry:8007",
}


@app.get("/")
async def root():
    """Root endpoint with platform information"""
    return {
        "platform": "CosmicSec",
        "tagline": "Universal Cybersecurity Intelligence Platform",
        "interface": "GuardAxisSphere",
        "ai_engine": "Helix AI",
        "version": "1.0.0",
        "status": "operational",
        "documentation": "/api/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "services": {
            "api_gateway": "operational",
            "database": "connected",
            "cache": "connected"
        }
    }


@app.get("/api/status")
@limiter.limit("100/minute")
async def api_status(request: Request):
    """Get detailed status of all microservices"""
    service_status = {}

    async with httpx.AsyncClient() as client:
        for service_name, service_url in SERVICE_URLS.items():
            try:
                response = await client.get(f"{service_url}/health", timeout=2.0)
                service_status[service_name] = {
                    "status": "healthy" if response.status_code == 200 else "unhealthy",
                    "response_time": response.elapsed.total_seconds()
                }
            except Exception as e:
                service_status[service_name] = {
                    "status": "unreachable",
                    "error": str(e)
                }

    return {
        "gateway": "operational",
        "services": service_status,
        "timestamp": time.time()
    }


# Authentication endpoints (proxy to auth service)
@app.post("/api/auth/register")
@limiter.limit("5/minute")
async def register(request: Request):
    """Proxy registration request to auth service"""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SERVICE_URLS['auth']}/register",
                json=data,
                timeout=10.0
            )
            return JSONResponse(
                status_code=response.status_code,
                content=response.json()
            )
        except Exception as e:
            logger.error(f"Auth service error: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable"
            )


@app.post("/api/auth/login")
@limiter.limit("10/minute")
async def login(request: Request):
    """Proxy login request to auth service"""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SERVICE_URLS['auth']}/login",
                json=data,
                timeout=10.0
            )
            return JSONResponse(
                status_code=response.status_code,
                content=response.json()
            )
        except Exception as e:
            logger.error(f"Auth service error: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable"
            )


@app.post("/api/auth/refresh")
@limiter.limit("20/minute")
async def refresh_token(request: Request):
    """Refresh JWT token"""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SERVICE_URLS['auth']}/refresh",
                json=data,
                timeout=10.0
            )
            return JSONResponse(
                status_code=response.status_code,
                content=response.json()
            )
        except Exception as e:
            logger.error(f"Auth service error: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable"
            )


# Scan endpoints (proxy to scan service)
@app.post("/api/scans")
@limiter.limit("30/minute")
async def create_scan(request: Request):
    """Create a new security scan"""
    data = await request.json()
    # TODO: Add authentication token validation

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SERVICE_URLS['scan']}/scans",
                json=data,
                timeout=30.0
            )
            return JSONResponse(
                status_code=response.status_code,
                content=response.json()
            )
        except Exception as e:
            logger.error(f"Scan service error: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Scan service unavailable"
            )


@app.get("/api/scans/{scan_id}")
@limiter.limit("60/minute")
async def get_scan(request: Request, scan_id: str):
    """Get scan details by ID"""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{SERVICE_URLS['scan']}/scans/{scan_id}",
                timeout=10.0
            )
            return JSONResponse(
                status_code=response.status_code,
                content=response.json()
            )
        except Exception as e:
            logger.error(f"Scan service error: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Scan service unavailable"
            )


@app.get("/api/info")
async def platform_info():
    """Get platform information and branding"""
    return {
        "project": {
            "name": "CosmicSec",
            "version": "1.0.0",
            "description": "Universal Cybersecurity Intelligence Platform"
        },
        "platform": {
            "name": "GuardAxisSphere",
            "tagline": "Enterprise Security Command Center",
            "description": "Multi-dimensional security platform for modern enterprises"
        },
        "ai_engine": {
            "name": "Helix AI",
            "tagline": "Your Intelligent Security Companion",
            "capabilities": [
                "Real-time threat analysis",
                "Vulnerability assessment",
                "Intelligent automation",
                "Exploit generation",
                "Code analysis"
            ]
        },
        "features": [
            "Multi-tenant architecture",
            "Distributed scanning",
            "AI-powered analysis",
            "Real-time collaboration",
            "Enterprise compliance"
        ]
    }


# AI service endpoints (Phase 2 — ChromaDB + MITRE ATT&CK + LangChain)
@app.get("/api/ai/health")
@limiter.limit("60/minute")
async def ai_health(request: Request):
    """Proxy AI service health endpoint"""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{SERVICE_URLS['ai']}/health", timeout=5.0)
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            logger.error(f"AI service error: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="AI service unavailable"
            )


@app.post("/api/ai/analyze")
@limiter.limit("30/minute")
async def ai_analyze(request: Request):
    """Proxy AI service analyze endpoint"""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SERVICE_URLS['ai']}/analyze",
                json=data,
                timeout=15.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            logger.error(f"AI service error: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="AI service unavailable"
            )


@app.post("/api/ai/analyze/agent")
@limiter.limit("20/minute")
async def ai_analyze_agent(request: Request):
    """Proxy AI LangChain agent analysis."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SERVICE_URLS['ai']}/analyze/agent",
                json=data,
                timeout=30.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            logger.error(f"AI service error: {e}")
            raise HTTPException(status_code=503, detail="AI service unavailable")


@app.post("/api/ai/analyze/mitre")
@limiter.limit("30/minute")
async def ai_mitre(request: Request):
    """Proxy MITRE ATT&CK correlation endpoint."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SERVICE_URLS['ai']}/analyze/mitre",
                json=data,
                timeout=10.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            logger.error(f"AI service error: {e}")
            raise HTTPException(status_code=503, detail="AI service unavailable")


@app.post("/api/ai/query")
@limiter.limit("20/minute")
async def ai_nl_query(request: Request):
    """Proxy natural language security query to Helix AI."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SERVICE_URLS['ai']}/query",
                json=data,
                timeout=20.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            logger.error(f"AI service error: {e}")
            raise HTTPException(status_code=503, detail="AI service unavailable")


@app.post("/api/ai/kb/ingest")
@limiter.limit("10/minute")
async def ai_kb_ingest(request: Request):
    """Ingest a document into the ChromaDB knowledge base."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SERVICE_URLS['ai']}/kb/ingest",
                json=data,
                timeout=10.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            raise HTTPException(status_code=503, detail="AI service unavailable")


@app.get("/api/ai/kb/stats")
@limiter.limit("60/minute")
async def ai_kb_stats(request: Request):
    """Return ChromaDB knowledge base statistics."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{SERVICE_URLS['ai']}/kb/stats", timeout=5.0)
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            raise HTTPException(status_code=503, detail="AI service unavailable")


@app.post("/api/recon")
@limiter.limit("30/minute")
async def recon_lookup(request: Request):
    """Proxy recon request to recon service"""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SERVICE_URLS['recon']}/recon",
                json=data,
                timeout=15.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            logger.error(f"Recon service error: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Recon service unavailable"
            )


@app.post("/api/reports/generate")
@limiter.limit("20/minute")
async def generate_report(request: Request):
    """Proxy report generation request to report service"""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SERVICE_URLS['report']}/reports/generate",
                json=data,
                timeout=20.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            logger.error(f"Report service error: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Report service unavailable"
            )


@app.post("/api/webhooks/events")
@limiter.limit("120/minute")
async def webhook_events(request: Request):
    """Webhook ingress endpoint for external integrations."""
    payload = await request.json()
    return {
        "status": "received",
        "event_type": payload.get("event_type", "unknown"),
        "timestamp": time.time(),
    }


@app.get("/api/admin/users")
@limiter.limit("60/minute")
async def admin_list_users(request: Request):
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{SERVICE_URLS['auth']}/users", timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.post("/api/admin/users")
@limiter.limit("30/minute")
async def admin_create_user(request: Request):
    payload = await request.json()
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{SERVICE_URLS['auth']}/users", json=payload, timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.put("/api/admin/users/{email}")
@limiter.limit("30/minute")
async def admin_update_user(request: Request, email: str):
    payload = await request.json()
    async with httpx.AsyncClient() as client:
        response = await client.put(f"{SERVICE_URLS['auth']}/users/{email}", json=payload, timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.delete("/api/admin/users/{email}")
@limiter.limit("30/minute")
async def admin_delete_user(request: Request, email: str):
    async with httpx.AsyncClient() as client:
        response = await client.delete(f"{SERVICE_URLS['auth']}/users/{email}", timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.post("/api/admin/roles/assign")
@limiter.limit("30/minute")
async def admin_assign_role(request: Request):
    payload = await request.json()
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{SERVICE_URLS['auth']}/roles/assign", json=payload, timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.get("/api/admin/config")
@limiter.limit("60/minute")
async def admin_get_config(request: Request):
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{SERVICE_URLS['auth']}/config", timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.post("/api/admin/config")
@limiter.limit("30/minute")
async def admin_set_config(request: Request):
    payload = await request.json()
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{SERVICE_URLS['auth']}/config", json=payload, timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.get("/api/admin/audit-logs")
@limiter.limit("60/minute")
async def admin_get_audit_logs(request: Request):
    query = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{SERVICE_URLS['auth']}/audit-logs", params=query, timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.websocket("/ws/dashboard")
async def dashboard_stream(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            payload = {
                "timestamp": time.time(),
                "system_health": "healthy",
                "active_scans": 0,
                "user_activity": "normal",
                "resource_utilization": {
                    "cpu": 22,
                    "memory": 48,
                    "network": 31,
                },
            }
            await websocket.send_json(payload)
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        logger.info("Dashboard websocket disconnected")


# ---------------------------------------------------------------------------
# Phase 2 — Collab service proxy routes
# ---------------------------------------------------------------------------

@app.get("/api/collab/rooms")
@limiter.limit("60/minute")
async def collab_list_rooms(request: Request):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{SERVICE_URLS['collab']}/rooms", timeout=5.0)
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


@app.get("/api/collab/rooms/{room_id}/messages")
@limiter.limit("60/minute")
async def collab_get_messages(request: Request, room_id: str):
    params = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{SERVICE_URLS['collab']}/rooms/{room_id}/messages",
                params=params,
                timeout=5.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


@app.post("/api/collab/rooms/{room_id}/messages")
@limiter.limit("60/minute")
async def collab_post_message(request: Request, room_id: str):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SERVICE_URLS['collab']}/rooms/{room_id}/messages",
                json=data,
                timeout=5.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


@app.get("/api/collab/rooms/{room_id}/presence")
@limiter.limit("60/minute")
async def collab_presence(request: Request, room_id: str):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{SERVICE_URLS['collab']}/rooms/{room_id}/presence", timeout=5.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


@app.get("/api/collab/activity-feed")
@limiter.limit("30/minute")
async def collab_activity_feed(request: Request):
    params = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{SERVICE_URLS['collab']}/activity-feed", params=params, timeout=5.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


# ---------------------------------------------------------------------------
# Phase 2 — Plugin registry proxy routes
# ---------------------------------------------------------------------------

@app.get("/api/plugins")
@limiter.limit("60/minute")
async def plugins_list(request: Request):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{SERVICE_URLS['plugins']}/plugins", timeout=5.0)
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.get("/api/plugins/{name}")
@limiter.limit("60/minute")
async def plugin_detail(request: Request, name: str):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{SERVICE_URLS['plugins']}/plugins/{name}", timeout=5.0)
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/plugins/{name}/run")
@limiter.limit("20/minute")
async def plugin_run(request: Request, name: str):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SERVICE_URLS['plugins']}/plugins/{name}/run",
                json=data,
                timeout=30.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/plugins/{name}/enable")
@limiter.limit("20/minute")
async def plugin_enable(request: Request, name: str):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SERVICE_URLS['plugins']}/plugins/{name}/enable", timeout=5.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/plugins/{name}/disable")
@limiter.limit("20/minute")
async def plugin_disable(request: Request, name: str):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                f"{SERVICE_URLS['plugins']}/plugins/{name}/disable", timeout=5.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


# ==========================================================================
# Phase 2 — New proxy routes: monitoring, fuzzing, container, smart scan
# ==========================================================================

# Continuous monitoring -------------------------------------------------------

@app.post("/api/scan/monitor/schedule")
@limiter.limit("20/minute")
async def scan_monitor_schedule(request: Request):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['scan']}/monitor/schedule", json=data, timeout=10.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.get("/api/scan/monitor/jobs")
@limiter.limit("30/minute")
async def scan_monitor_jobs(request: Request):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{SERVICE_URLS['scan']}/monitor/jobs", timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.get("/api/scan/monitor/jobs/{job_id}")
@limiter.limit("30/minute")
async def scan_monitor_job_detail(request: Request, job_id: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{SERVICE_URLS['scan']}/monitor/jobs/{job_id}", timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.post("/api/scan/monitor/jobs/{job_id}/pause")
@limiter.limit("20/minute")
async def scan_monitor_pause(request: Request, job_id: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['scan']}/monitor/jobs/{job_id}/pause", timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.post("/api/scan/monitor/jobs/{job_id}/resume")
@limiter.limit("20/minute")
async def scan_monitor_resume(request: Request, job_id: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['scan']}/monitor/jobs/{job_id}/resume", timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.delete("/api/scan/monitor/jobs/{job_id}")
@limiter.limit("20/minute")
async def scan_monitor_cancel(request: Request, job_id: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.delete(f"{SERVICE_URLS['scan']}/monitor/jobs/{job_id}", timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


# API fuzzing -----------------------------------------------------------------

@app.post("/api/scans/fuzz")
@limiter.limit("10/minute")
async def scans_fuzz(request: Request):
    """Run an API security fuzzing campaign."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['scan']}/scans/fuzz", json=data, timeout=60.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


# Container / K8s scanning ----------------------------------------------------

@app.post("/api/scans/container")
@limiter.limit("20/minute")
async def scans_container(request: Request):
    """Scan a Dockerfile or Kubernetes manifest for security issues."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['scan']}/scans/container", json=data, timeout=30.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


# Smart scan plan -------------------------------------------------------------

@app.post("/api/scans/smart-plan")
@limiter.limit("20/minute")
async def scans_smart_plan(request: Request):
    """AI-driven scan plan optimisation via technology fingerprinting."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['scan']}/scans/smart-plan", json=data, timeout=30.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


# Cloud configuration scan ----------------------------------------------------

@app.post("/api/scans/cloud")
@limiter.limit("10/minute")
async def scans_cloud(request: Request):
    """Cloud infrastructure security scan (AWS / Azure / GCP / K8s)."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['scan']}/scans/cloud", json=data, timeout=30.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


# ==========================================================================
# Phase 2 — AI service new routes
# ==========================================================================

@app.post("/api/ai/agent/autonomous")
@limiter.limit("10/minute")
async def ai_agent_autonomous(request: Request):
    """Autonomous multi-step AI security analysis agent."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['ai']}/agent/autonomous", json=data, timeout=60.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="AI service unavailable")


@app.post("/api/ai/exploit/suggest")
@limiter.limit("20/minute")
async def ai_exploit_suggest(request: Request):
    """Educational CVE exploit guidance and remediation advice."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['ai']}/exploit/suggest", json=data, timeout=30.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="AI service unavailable")


@app.post("/api/ai/anomaly/fit")
@limiter.limit("10/minute")
async def ai_anomaly_fit(request: Request):
    """Train the anomaly detector on historical scan baseline data."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['ai']}/anomaly/fit", json=data, timeout=30.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="AI service unavailable")


@app.post("/api/ai/anomaly/detect")
@limiter.limit("30/minute")
async def ai_anomaly_detect(request: Request):
    """Score a single scan result for anomalousness."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['ai']}/anomaly/detect", json=data, timeout=15.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="AI service unavailable")


@app.post("/api/ai/anomaly/batch")
@limiter.limit("10/minute")
async def ai_anomaly_batch(request: Request):
    """Batch anomaly detection across multiple scan records."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['ai']}/anomaly/batch", json=data, timeout=30.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="AI service unavailable")


# ==========================================================================
# Phase 2 — Collaborative report editing routes
# ==========================================================================

@app.post("/api/collab/rooms/{room_id}/reports")
@limiter.limit("30/minute")
async def collab_create_report_section(request: Request, room_id: str):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['collab']}/rooms/{room_id}/reports", json=data, timeout=10.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


@app.get("/api/collab/rooms/{room_id}/reports")
@limiter.limit("60/minute")
async def collab_list_report_sections(request: Request, room_id: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{SERVICE_URLS['collab']}/rooms/{room_id}/reports", timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


@app.put("/api/collab/rooms/{room_id}/reports/{section_id}")
@limiter.limit("30/minute")
async def collab_update_report_section(request: Request, room_id: str, section_id: str):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.put(
                f"{SERVICE_URLS['collab']}/rooms/{room_id}/reports/{section_id}",
                json=data,
                timeout=10.0,
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


@app.delete("/api/collab/rooms/{room_id}/reports/{section_id}")
@limiter.limit("20/minute")
async def collab_delete_report_section(request: Request, room_id: str, section_id: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.delete(
                f"{SERVICE_URLS['collab']}/rooms/{room_id}/reports/{section_id}",
                timeout=5.0,
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


@app.get("/api/collab/rooms/{room_id}/reports/{section_id}/history")
@limiter.limit("30/minute")
async def collab_section_history(request: Request, room_id: str, section_id: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"{SERVICE_URLS['collab']}/rooms/{room_id}/reports/{section_id}/history",
                timeout=5.0,
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


# Plugin marketplace routes ---------------------------------------------------

@app.get("/api/marketplace")
@limiter.limit("60/minute")
async def marketplace_list(request: Request):
    """Browse the plugin community marketplace."""
    params = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{SERVICE_URLS['plugins']}/marketplace", params=params, timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/marketplace/publish")
@limiter.limit("10/minute")
async def marketplace_publish(request: Request):
    """Publish a plugin to the community marketplace."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['plugins']}/marketplace/publish", json=data, timeout=10.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/plugins/{name}/rate")
@limiter.limit("20/minute")
async def plugin_rate(request: Request, name: str):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['plugins']}/plugins/{name}/rate", json=data, timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.get("/api/plugins/{name}/rating")
@limiter.limit("60/minute")
async def plugin_rating(request: Request, name: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{SERVICE_URLS['plugins']}/plugins/{name}/rating", timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
