"""
CosmicSec API Gateway
Main entry point for all API requests with routing, authentication, and rate limiting
"""
from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import httpx
import time
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
    "report": "http://report-service:8004"
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
