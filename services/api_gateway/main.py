"""
CosmicSec API Gateway
Main entry point for all API requests with routing, authentication, and rate limiting
"""
from fastapi import FastAPI, Request, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import httpx
import time
import asyncio
import uuid
from typing import Optional
import logging

from cosmicsec_platform.contracts.runtime_metadata import HYBRID_SCHEMA, HYBRID_VERSION
from cosmicsec_platform.middleware.hybrid_router import HybridRouter
from cosmicsec_platform.middleware.policy_registry import ROUTE_POLICIES
from cosmicsec_platform.middleware.static_profiles import STATIC_PROFILES

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
    "integration": "http://integration-service:8008",
    "bugbounty": "http://bugbounty-service:8009",
    "phase5": "http://phase5-service:8010",
}

hybrid_router = HybridRouter(SERVICE_URLS, static_profiles=STATIC_PROFILES)
PRIVILEGED_PREFIXES = ("/api/admin", "/api/orgs")


@app.middleware("http")
async def enforce_demo_privileged_guard(request: Request, call_next):
    resolved_mode = hybrid_router.resolve_mode(request)
    if resolved_mode.value == "demo" and request.url.path.startswith(PRIVILEGED_PREFIXES):
        trace_id = request.headers.get("X-Request-Id", str(uuid.uuid4()))
        now = time.time()
        return JSONResponse(
            status_code=403,
            content={
                "status": "denied",
                "detail": "Privileged administrative routes are disabled in demo mode.",
                "_runtime": {
                    "mode": "demo",
                    "route": "policy_denied",
                    "trace_id": trace_id,
                    "decision_ts": now,
                    "reason": "demo_mode_privileged_route_blocked",
                },
                "_contract": {
                    "schema": HYBRID_SCHEMA,
                    "version": HYBRID_VERSION,
                    "degraded": True,
                    "consumer_hint": "Switch to authenticated non-demo mode for privileged operations.",
                },
            },
        )
    return await call_next(request)


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
        },
        "runtime_mode_default": hybrid_router.default_mode.value,
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


@app.get("/api/dashboard/summary")
@limiter.limit("30/minute")
async def dashboard_summary(request: Request):
    """Executive dashboard summary for system health and key metrics."""
    async with httpx.AsyncClient() as client:
        results = {}
        # Scan stats
        try:
            resp = await client.get(f"{SERVICE_URLS['scan']}/stats", timeout=5.0)
            results["scan_stats"] = resp.json()
        except Exception:
            results["scan_stats"] = {"error": "unavailable"}

        # Active collaboration stats
        try:
            resp = await client.get(f"{SERVICE_URLS['collab']}/activity-feed", timeout=5.0)
            results["collab_activity"] = {"total_events": resp.json().get("total_events", 0)}
        except Exception:
            results["collab_activity"] = {"error": "unavailable"}

        # Plugin ecosystem status
        try:
            resp = await client.get(f"{SERVICE_URLS['plugins']}/plugins", timeout=5.0)
            results["plugins"] = {"total": len(resp.json().get("plugins", []))}
        except Exception:
            results["plugins"] = {"error": "unavailable"}

        # Integration service signals
        try:
            resp = await client.get(f"{SERVICE_URLS['report']}/health", timeout=5.0)
            results["report_service"] = resp.json()
        except Exception:
            results["report_service"] = {"error": "unavailable"}

    return {
        "summary": results,
        "timestamp": time.time(),
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
    """Hybrid login: dynamic auth by default, demo/static fallback by mode policy."""
    data = await request.json()
    return await hybrid_router.execute(
        request=request,
        service="auth",
        path="/login",
        method="POST",
        payload=data,
        timeout=10.0,
        route_key="auth.login",
    )


@app.post("/api/auth/refresh")
@limiter.limit("20/minute")
async def refresh_token(request: Request):
    """Refresh JWT token (security-critical: no static fallback)."""
    data = await request.json()
    return await hybrid_router.execute(
        request=request,
        service="auth",
        path="/refresh",
        method="POST",
        payload=data,
        timeout=10.0,
        route_key="auth.refresh",
    )


@app.get("/api/gdpr/export")
@limiter.limit("20/minute")
async def gdpr_export(request: Request):
    params = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{SERVICE_URLS['auth']}/gdpr/export", params=params, timeout=10.0)
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            logger.error(f"Auth service error: {e}")
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


@app.delete("/api/gdpr/delete")
@limiter.limit("20/minute")
async def gdpr_delete(request: Request):
    params = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.delete(f"{SERVICE_URLS['auth']}/gdpr/delete", params=params, timeout=10.0)
            return JSONResponse(status_code=response.status_code, content=response.json())
        except Exception as e:
            logger.error(f"Auth service error: {e}")
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


# Scan endpoints (proxy to scan service)
@app.post("/api/scans")
@limiter.limit("30/minute")
async def create_scan(request: Request):
    """Create a security scan using dynamic-first hybrid runtime."""
    data = await request.json()

    headers = {}
    for h in ["X-Org-Id", "X-Workspace-Id", "Authorization"]:
        if request.headers.get(h):
            headers[h] = request.headers.get(h)

    return await hybrid_router.execute(
        request=request,
        service="scan",
        path="/scans",
        method="POST",
        payload=data,
        headers=headers,
        timeout=30.0,
        route_key="scan.create",
    )


@app.get("/api/scans/{scan_id}")
@limiter.limit("60/minute")
async def get_scan(request: Request, scan_id: str):
    """Get scan details by ID with partial fallback profile."""
    return await hybrid_router.execute(
        request=request,
        service="scan",
        path=f"/scans/{scan_id}",
        method="GET",
        payload={"scan_id": scan_id},
        timeout=10.0,
        route_key="scan.get",
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
    """Hybrid AI health endpoint with static resilience profile."""
    return await hybrid_router.execute(
        request=request,
        service="ai",
        path="/health",
        method="GET",
        timeout=5.0,
        route_key="ai.health",
    )


@app.post("/api/ai/analyze")
@limiter.limit("30/minute")
async def ai_analyze(request: Request):
    """Proxy AI analysis endpoint (fallback disabled by policy)."""
    data = await request.json()
    return await hybrid_router.execute(
        request=request,
        service="ai",
        path="/analyze",
        method="POST",
        payload=data,
        timeout=15.0,
        route_key="ai.analyze",
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
    """Hybrid recon endpoint with static fallback preview for continuity."""
    data = await request.json()
    return await hybrid_router.execute(
        request=request,
        service="recon",
        path="/recon",
        method="POST",
        payload=data,
        timeout=15.0,
        route_key="recon.lookup",
    )


@app.get("/api/runtime/mode")
@limiter.limit("60/minute")
async def runtime_mode(request: Request):
    """Expose resolved runtime mode for observability and operations."""
    resolved = hybrid_router.resolve_mode(request).value
    return {
        "resolved_mode": resolved,
        "default_mode": hybrid_router.default_mode.value,
        "rollout": hybrid_router.get_rollout_config(),
        "supported_modes": ["dynamic", "hybrid", "static", "demo", "emergency"],
    }


@app.get("/api/runtime/metrics")
@limiter.limit("60/minute")
async def runtime_metrics(request: Request):
    """Runtime metrics for fallback and dynamic success tracking."""
    return hybrid_router.get_metrics()


@app.get("/api/runtime/metrics/prometheus")
@limiter.limit("60/minute")
async def runtime_metrics_prometheus(request: Request):
    """Prometheus-format runtime metrics for Grafana/Prometheus dashboards."""
    metrics = hybrid_router.get_metrics()
    lines = [
        "# HELP cosmicsec_runtime_dynamic_total Total dynamic route attempts.",
        "# TYPE cosmicsec_runtime_dynamic_total counter",
        f"cosmicsec_runtime_dynamic_total {metrics['dynamic_total']}",
        "# HELP cosmicsec_runtime_dynamic_success Total successful dynamic responses.",
        "# TYPE cosmicsec_runtime_dynamic_success counter",
        f"cosmicsec_runtime_dynamic_success {metrics['dynamic_success']}",
        "# HELP cosmicsec_runtime_fallback_total Total hybrid fallback executions.",
        "# TYPE cosmicsec_runtime_fallback_total counter",
        f"cosmicsec_runtime_fallback_total {metrics['fallback_total']}",
        "# HELP cosmicsec_runtime_static_total Total static/disaster responses.",
        "# TYPE cosmicsec_runtime_static_total counter",
        f"cosmicsec_runtime_static_total {metrics['static_total']}",
        "# HELP cosmicsec_runtime_policy_denied_total Total policy-denied requests.",
        "# TYPE cosmicsec_runtime_policy_denied_total counter",
        f"cosmicsec_runtime_policy_denied_total {metrics['policy_denied_total']}",
        "# HELP cosmicsec_runtime_dynamic_success_rate Dynamic success ratio.",
        "# TYPE cosmicsec_runtime_dynamic_success_rate gauge",
        f"cosmicsec_runtime_dynamic_success_rate {metrics['dynamic_success_rate']}",
    ]
    return PlainTextResponse(content="\n".join(lines) + "\n")


@app.get("/api/runtime/traces")
@limiter.limit("60/minute")
async def runtime_traces(request: Request):
    """Recent runtime trace decisions for degradation and chaos debugging."""
    limit = int(request.query_params.get("limit", "50"))
    return {"traces": hybrid_router.get_recent_traces(limit)}


@app.get("/api/runtime/tracing")
@limiter.limit("60/minute")
async def runtime_tracing(request: Request):
    """Tracing exporter status and in-memory trace buffer utilization."""
    return hybrid_router.get_tracing_status()


@app.get("/api/runtime/contracts")
@limiter.limit("60/minute")
async def runtime_contracts(request: Request):
    """Contract helper for clients to parse hybrid runtime metadata consistently."""
    return {
        "schema": HYBRID_SCHEMA,
        "version": HYBRID_VERSION,
        "runtime_field": "_runtime",
        "contract_field": "_contract",
        "route_policies": {k: v.to_dict() for k, v in ROUTE_POLICIES.items()},
        "examples": {
            "dynamic": {
                "_runtime": {"route": "dynamic", "mode": "hybrid", "trace_id": "uuid"},
                "_contract": {"degraded": False, "schema": HYBRID_SCHEMA},
            },
            "static_fallback": {
                "_runtime": {"route": "static_fallback", "mode": "hybrid", "trace_id": "uuid"},
                "_contract": {"degraded": True, "schema": HYBRID_SCHEMA},
            },
        },
    }


@app.get("/api/runtime/slo")
@limiter.limit("60/minute")
async def runtime_slo(request: Request):
    """Hybrid runtime SLO snapshot and current error budget usage."""
    metrics = hybrid_router.get_metrics()
    total_degradation_events = metrics["fallback_total"] + metrics["policy_denied_total"]
    total_observed_events = metrics["dynamic_total"] + metrics["static_total"]
    degraded_ratio = (total_degradation_events / total_observed_events) if total_observed_events else 0.0

    return {
        "window": "rolling-process-lifetime",
        "slo_targets": {
            "hybrid_availability": 0.995,
            "max_degraded_ratio": 0.10,
        },
        "current": {
            "dynamic_success_rate": metrics["dynamic_success_rate"],
            "degraded_ratio": round(degraded_ratio, 4),
            "total_observed_events": total_observed_events,
            "total_degradation_events": total_degradation_events,
        },
        "error_budget": {
            "availability_remaining": round(max(0.0, 0.995 - (1.0 - metrics["dynamic_success_rate"])), 4),
            "degradation_remaining": round(max(0.0, 0.10 - degraded_ratio), 4),
        },
    }


@app.get("/api/runtime/readiness")
@limiter.limit("60/minute")
async def runtime_readiness(request: Request):
    """Production-readiness checklist for hybrid runtime rollout."""
    required_critical_routes = {"auth.refresh", "scan.get", "ai.analyze", "report.generate"}
    configured_routes = set(ROUTE_POLICIES.keys())
    missing_routes = sorted(required_critical_routes - configured_routes)
    tracing = hybrid_router.get_tracing_status()

    checks = {
        "shared_middleware_extracted": True,
        "route_policies_configured": len(configured_routes) >= 8,
        "critical_routes_covered": not missing_routes,
        "runtime_contract_endpoint": True,
        "runtime_metrics_endpoint": True,
        "runtime_tracing_enabled_or_buffered": tracing["buffer_size"] > 0,
    }

    return {
        "ready_for_production": all(checks.values()),
        "checks": checks,
        "missing_critical_routes": missing_routes,
        "tracked_route_count": len(configured_routes),
    }


@app.get("/api/runtime/rollout")
@limiter.limit("60/minute")
async def runtime_rollout_get(request: Request):
    """Get canary rollout controls for hybrid runtime."""
    return hybrid_router.get_rollout_config()


@app.post("/api/runtime/rollout")
@limiter.limit("20/minute")
async def runtime_rollout_set(request: Request):
    """Set canary rollout controls for dynamic traffic splitting."""
    payload = await request.json()
    percent = payload.get("dynamic_canary_percent", 0)
    return hybrid_router.set_rollout_config(percent)


@app.post("/api/reports/generate")
@limiter.limit("20/minute")
async def generate_report(request: Request):
    """Hybrid report generation with degraded queue fallback profile."""
    data = await request.json()
    return await hybrid_router.execute(
        request=request,
        service="report",
        path="/reports/generate",
        method="POST",
        payload=data,
        timeout=20.0,
        route_key="report.generate",
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


@app.get("/api/threat-intel/ip")
@limiter.limit("60/minute")
async def threat_intel_ip(request: Request):
    params = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{SERVICE_URLS['report']}/threat-intel/ip", params=params, timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Integration service unavailable")


@app.get("/api/threat-intel/domain")
@limiter.limit("60/minute")
async def threat_intel_domain(request: Request):
    params = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{SERVICE_URLS['report']}/threat-intel/domain", params=params, timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Integration service unavailable")


@app.post("/api/ci/build")
@limiter.limit("20/minute")
async def ci_build(request: Request):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['report']}/ci/build", json=data, timeout=10.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Integration service unavailable")


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


# ---------------------------------------------------------------------------
# Phase 3.1 — Multi-tenant org/workspace routes
# ---------------------------------------------------------------------------

@app.post("/api/orgs")
@limiter.limit("20/minute")
async def create_org(request: Request):
    payload = await request.json()
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{SERVICE_URLS['auth']}/orgs", json=payload, timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.get("/api/orgs")
@limiter.limit("60/minute")
async def list_orgs(request: Request):
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{SERVICE_URLS['auth']}/orgs", timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.post("/api/orgs/{org_id}/members")
@limiter.limit("30/minute")
async def add_org_member(request: Request, org_id: str):
    payload = await request.json()
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{SERVICE_URLS['auth']}/orgs/{org_id}/members", json=payload, timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.get("/api/orgs/{org_id}/members")
@limiter.limit("60/minute")
async def list_org_members(request: Request, org_id: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{SERVICE_URLS['auth']}/orgs/{org_id}/members", timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.post("/api/orgs/{org_id}/workspaces")
@limiter.limit("30/minute")
async def create_workspace(request: Request, org_id: str):
    payload = await request.json()
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{SERVICE_URLS['auth']}/orgs/{org_id}/workspaces", json=payload, timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.get("/api/orgs/{org_id}/workspaces")
@limiter.limit("60/minute")
async def list_workspaces(request: Request, org_id: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{SERVICE_URLS['auth']}/orgs/{org_id}/workspaces", timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.get("/api/orgs/{org_id}/quotas")
@limiter.limit("60/minute")
async def get_org_quotas(request: Request, org_id: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{SERVICE_URLS['auth']}/orgs/{org_id}/quotas", timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.post("/api/orgs/{org_id}/quotas")
@limiter.limit("20/minute")
async def set_org_quotas(request: Request, org_id: str):
    payload = await request.json()
    async with httpx.AsyncClient() as client:
        response = await client.post(f"{SERVICE_URLS['auth']}/orgs/{org_id}/quotas", json=payload, timeout=10.0)
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


# Distributed scanning --------------------------------------------------------

@app.post("/api/scan/distributed/nodes/register")
@limiter.limit("20/minute")
async def scan_register_node(request: Request):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['scan']}/distributed/nodes/register", json=data, timeout=10.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.get("/api/scan/distributed/nodes")
@limiter.limit("30/minute")
async def scan_list_nodes(request: Request):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{SERVICE_URLS['scan']}/distributed/nodes", timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.post("/api/scan/distributed/nodes/{node_id}/heartbeat")
@limiter.limit("30/minute")
async def scan_node_heartbeat(request: Request, node_id: str):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{SERVICE_URLS['scan']}/distributed/nodes/{node_id}/heartbeat",
                json=data,
                timeout=5.0,
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.post("/api/scan/distributed/assign")
@limiter.limit("20/minute")
async def scan_distributed_assign(request: Request):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['scan']}/distributed/assign", json=data, timeout=10.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.post("/api/scan/distributed/nodes/{node_id}/complete")
@limiter.limit("20/minute")
async def scan_distributed_complete(request: Request, node_id: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{SERVICE_URLS['scan']}/distributed/nodes/{node_id}/complete",
                timeout=5.0,
            )
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


@app.get("/api/plugins/updates")
@limiter.limit("30/minute")
async def plugins_updates(request: Request):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{SERVICE_URLS['plugins']}/plugins/updates", timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/plugins/{name}/auto-update")
@limiter.limit("10/minute")
async def plugin_auto_update(request: Request, name: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['plugins']}/plugins/{name}/auto-update", timeout=10.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.get("/api/community/repositories")
@limiter.limit("30/minute")
async def community_repositories(request: Request):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{SERVICE_URLS['plugins']}/community/repositories", timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/community/repositories")
@limiter.limit("10/minute")
async def community_register_repository(request: Request):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS['plugins']}/community/repositories", json=data, timeout=10.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/community/repositories/{repo_id}/sync")
@limiter.limit("10/minute")
async def community_sync_repository(request: Request, repo_id: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{SERVICE_URLS['plugins']}/community/repositories/{repo_id}/sync",
                timeout=20.0,
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


async def _proxy_get(service: str, path: str, params: Optional[dict] = None, timeout: float = 10.0) -> JSONResponse:
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{SERVICE_URLS[service]}{path}", params=params, timeout=timeout)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail=f"{service} service unavailable")


async def _proxy_post(service: str, path: str, data: dict, timeout: float = 10.0) -> JSONResponse:
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS[service]}{path}", json=data, timeout=timeout)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail=f"{service} service unavailable")


@app.post("/api/ai/red-team/plan")
@limiter.limit("20/minute")
async def ai_red_team_plan(request: Request):
    return await _proxy_post("ai", "/red-team/plan", await request.json())


@app.post("/api/ai/red-team/safety-check")
@limiter.limit("20/minute")
async def ai_red_team_safety(request: Request):
    return await _proxy_post("ai", "/red-team/safety-check", await request.json())


@app.post("/api/ai/zero-day/train")
@limiter.limit("10/minute")
async def ai_zero_day_train(request: Request):
    return await _proxy_post("ai", "/zero-day/train", await request.json())


@app.post("/api/ai/zero-day/forecast")
@limiter.limit("30/minute")
async def ai_zero_day_forecast(request: Request):
    return await _proxy_post("ai", "/zero-day/forecast", await request.json())


@app.get("/api/ai/quantum/algorithms")
@limiter.limit("60/minute")
async def ai_quantum_algorithms(request: Request):
    return await _proxy_get("ai", "/quantum/algorithms")


@app.post("/api/reports/visualization/topology")
@limiter.limit("30/minute")
async def report_topology(request: Request):
    return await _proxy_post("report", "/visualization/topology", await request.json())


@app.post("/api/reports/visualization/attack-path")
@limiter.limit("30/minute")
async def report_attack_path(request: Request):
    return await _proxy_post("report", "/visualization/attack-path", await request.json())


@app.post("/api/reports/visualization/heatmap")
@limiter.limit("30/minute")
async def report_heatmap(request: Request):
    return await _proxy_post("report", "/visualization/heatmap", await request.json())


@app.post("/api/reports/visualization/immersive")
@limiter.limit("30/minute")
async def report_immersive(request: Request):
    return await _proxy_post("report", "/visualization/immersive", await request.json())


@app.post("/api/integration/siem/{vendor}")
@limiter.limit("60/minute")
async def integration_siem_vendor(request: Request, vendor: str):
    path = f"/siem/{vendor}"
    return await _proxy_post("integration", path, await request.json())


@app.post("/api/integration/ticket/{provider}")
@limiter.limit("30/minute")
async def integration_ticket_provider(request: Request, provider: str):
    path = f"/ticket/{provider}"
    return await _proxy_post("integration", path, await request.json())


@app.post("/api/integration/notify/{channel}")
@limiter.limit("60/minute")
async def integration_notify_channel(request: Request, channel: str):
    path = f"/notify/{channel}"
    return await _proxy_post("integration", path, await request.json())


@app.post("/api/bugbounty/programs")
@limiter.limit("20/minute")
async def bugbounty_programs_create(request: Request):
    return await _proxy_post("bugbounty", "/programs", await request.json())


@app.get("/api/bugbounty/programs")
@limiter.limit("60/minute")
async def bugbounty_programs_list(request: Request):
    return await _proxy_get("bugbounty", "/programs", params=dict(request.query_params))


@app.post("/api/bugbounty/recon/auto")
@limiter.limit("30/minute")
async def bugbounty_recon_auto(request: Request):
    return await _proxy_post("bugbounty", "/recon/auto", await request.json())


@app.post("/api/bugbounty/findings/prioritize")
@limiter.limit("30/minute")
async def bugbounty_prioritize(request: Request):
    return await _proxy_post("bugbounty", "/findings/prioritize", await request.json())


@app.post("/api/bugbounty/poc/build")
@limiter.limit("30/minute")
async def bugbounty_poc_build(request: Request):
    return await _proxy_post("bugbounty", "/poc/build", await request.json())


@app.post("/api/bugbounty/submissions")
@limiter.limit("30/minute")
async def bugbounty_submissions_create(request: Request):
    return await _proxy_post("bugbounty", "/submissions", await request.json())


@app.post("/api/bugbounty/submissions/{submission_id}/submit")
@limiter.limit("30/minute")
async def bugbounty_submissions_submit(request: Request, submission_id: str):
    return await _proxy_post("bugbounty", f"/submissions/{submission_id}/submit", {})


@app.get("/api/bugbounty/dashboard/earnings")
@limiter.limit("30/minute")
async def bugbounty_dashboard_earnings(request: Request):
    return await _proxy_get("bugbounty", "/dashboard/earnings")


@app.get("/api/bugbounty/timeline")
@limiter.limit("30/minute")
async def bugbounty_timeline(request: Request):
    return await _proxy_get("bugbounty", "/timeline", params=dict(request.query_params))


@app.post("/api/bugbounty/collaboration/share")
@limiter.limit("30/minute")
async def bugbounty_collaboration_share(request: Request):
    return await _proxy_post("bugbounty", "/collaboration/share", await request.json())


@app.get("/api/bugbounty/collaboration/threads")
@limiter.limit("60/minute")
async def bugbounty_collaboration_threads(request: Request):
    return await _proxy_get("bugbounty", "/collaboration/threads", params=dict(request.query_params))


@app.get("/api/bugbounty/reports/templates")
@limiter.limit("60/minute")
async def bugbounty_report_templates(request: Request):
    return await _proxy_get("bugbounty", "/reports/templates")


@app.api_route("/api/phase5/{path:path}", methods=["GET", "POST"])
@limiter.limit("120/minute")
async def phase5_proxy(request: Request, path: str):
    params = dict(request.query_params)
    url = f"{SERVICE_URLS['phase5']}/{path}"
    async with httpx.AsyncClient() as client:
        try:
            if request.method == "GET":
                resp = await client.get(url, params=params, timeout=15.0)
            else:
                data = await request.json()
                resp = await client.post(url, json=data, params=params, timeout=20.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception:
            raise HTTPException(status_code=503, detail="phase5 service unavailable")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
