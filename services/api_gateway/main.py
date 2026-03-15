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
    "report": "http://report-service:8005"
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


# AI service endpoints (Phase 2 kickoff)
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
