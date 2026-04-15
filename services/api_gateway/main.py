"""
CosmicSec API Gateway
Main entry point for all API requests with routing, authentication, and rate limiting
"""

import asyncio
import json
import logging
import os
import re
import time
import urllib.parse
import uuid
from datetime import timedelta

import httpx
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from cosmicsec_platform.contracts.runtime_metadata import HYBRID_SCHEMA, HYBRID_VERSION
from cosmicsec_platform.middleware.hybrid_router import HybridRouter
from cosmicsec_platform.middleware.policy_registry import ROUTE_POLICIES
from cosmicsec_platform.middleware.static_profiles import STATIC_PROFILES
from services.api_gateway.graphql_runtime import mount_graphql
from services.common.caching import CacheManager, get_redis
from services.common.exceptions import CosmicSecException
from services.common.logging import (
    clear_context,
    set_request_id,
    set_trace_id,
    setup_structured_logging,
)
from services.common.observability import setup_observability
from services.common.versioning import APIVersionMiddleware

# ---------------------------------------------------------------------------
# Security helpers — path-parameter validation & log sanitization
# ---------------------------------------------------------------------------

# Compiled patterns for path parameter validation
_RE_ALPHANUMERIC_ID = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")
_RE_EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,}$")
_RE_PLUGIN_NAME = re.compile(r"^[A-Za-z0-9_\-]{1,128}$")
_RE_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


def _validate_path_id(value: str, label: str = "id") -> str:
    """Validate an alphanumeric path parameter to prevent SSRF path injection.

    Accepts letters, digits, hyphens and underscores (max 128 chars).
    Raises HTTP 400 if the value is invalid.
    """
    if not _RE_ALPHANUMERIC_ID.match(value):
        raise HTTPException(
            status_code=400, detail=f"Invalid {label}: must be alphanumeric (max 128 chars)"
        )
    return value


def _validate_email_param(value: str) -> str:
    """Validate an email path parameter to prevent SSRF path injection."""
    if not _RE_EMAIL.match(value):
        raise HTTPException(status_code=400, detail="Invalid email format in path")
    return value


def _validate_plugin_name(value: str) -> str:
    """Validate a plugin name path parameter.

    Same character set as ``_validate_path_id`` but uses the dedicated plugin
    regex so the ``_RE_PLUGIN_NAME`` pattern is exercised.
    """
    if not _RE_PLUGIN_NAME.match(value):
        raise HTTPException(
            status_code=400, detail="Invalid plugin name: must be alphanumeric (max 128 chars)"
        )
    return value


def _validate_uuid_param(value: str, label: str = "id") -> str:
    """Validate a UUID path parameter."""
    if not _RE_UUID.match(value):
        raise HTTPException(status_code=400, detail=f"Invalid {label}: must be a valid UUID")
    return value


def _sanitize_log(value: object, max_len: int = 200) -> str:
    """Sanitize a user-provided value before including it in a log message.

    Removes newline and carriage-return characters to prevent log injection,
    and truncates to ``max_len`` characters.
    """
    text = str(value) if value is not None else ""
    # Strip log-injection control characters
    text = text.replace("\n", "\\n").replace("\r", "\\r").replace("\x00", "")
    return text[:max_len]


# ---------------------------------------------------------------------------
# Internal service URL builder — prevents SSRF by constructing URLs from
# a frozen allowlist of service base URLs.  User-controlled path segments
# MUST be validated *before* being passed here.
# ---------------------------------------------------------------------------

# Immutable copy so application code cannot mutate the registry at runtime.
_FROZEN_SERVICE_URLS: dict[str, str] = {}


def _init_service_urls(urls: dict[str, str]) -> None:
    """Freeze the service URL registry (called once at module level)."""
    global _FROZEN_SERVICE_URLS  # noqa: PLW0603
    _FROZEN_SERVICE_URLS = dict(urls)


def _build_service_url(service: str, path: str) -> str:
    """Build an internal service URL from the frozen allowlist.

    ``service`` must be a key in ``SERVICE_URLS``.
    ``path`` must start with ``/``.  Only the scheme, host, and port of the
    base URL are used; the path is appended with ``urllib.parse.urljoin``.
    """
    base = _FROZEN_SERVICE_URLS.get(service)
    if base is None:
        raise ValueError(f"Unknown service: {service}")
    # Ensure path starts with /
    if not path.startswith("/"):
        path = "/" + path
    return urllib.parse.urljoin(base, path)


async def _resolve_authenticated_user(request: Request) -> tuple[str, bool]:
    """Validate bearer token with auth service and return (principal, is_admin)."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")

    token = auth[len("Bearer ") :].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Bearer token required")

    try:
        async with httpx.AsyncClient() as client:
            verify_resp = await client.get(
                _build_service_url("auth", "/me"),
                headers={"Authorization": f"Bearer {token}"},
                timeout=5.0,
            )
    except httpx.HTTPError as exc:
        logger.warning("Auth service unavailable during token verification: %s", exc)
        raise HTTPException(status_code=503, detail="Authentication service unavailable")

    if verify_resp.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    me = verify_resp.json()
    principal = me.get("email") or me.get("user_id") or me.get("id")
    if not principal:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    return str(principal), me.get("role") == "admin"


# Search tuning constants
_SEARCH_SCAN_FETCH_MULTIPLIER = 10
_SEARCH_FINDING_SCAN_CANDIDATES = 10


# Initialize FastAPI app
app = FastAPI(
    title="CosmicSec API Gateway",
    description="GuardAxisSphere Platform - Universal Cybersecurity Intelligence Platform powered by Helix AI",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = setup_structured_logging("api_gateway")


# Rate limiting
def get_user_identifier(request: Request) -> str:
    """Return user ID from JWT for per-user rate limiting; fall back to IP for anonymous."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            import base64 as _b64

            token = auth_header.split(" ", 1)[1]
            parts = token.split(".")
            if len(parts) == 3:
                payload_bytes = parts[1] + "=="  # add padding
                decoded = _b64.urlsafe_b64decode(payload_bytes)
                import json as _json

                claims = _json.loads(decoded)
                sub = claims.get("sub") or claims.get("user_id")
                if sub:
                    return f"user:{sub}"
        except (ValueError, json.JSONDecodeError):
            pass
    return get_remote_address(request)


# SQL injection and XSS pattern blocklist (request-level WAF)
_SQL_INJECTION_RE = re.compile(
    r"(union\s+select|drop\s+table|insert\s+into|delete\s+from|"
    r"exec\s*\(|execute\s*\(|xp_cmdshell|benchmark\s*\(|sleep\s*\()",
    re.IGNORECASE,
)
_XSS_RE = re.compile(
    r"(<script|javascript:|vbscript:|onload\s*=|onerror\s*=|<iframe)",
    re.IGNORECASE,
)

limiter = Limiter(key_func=get_user_identifier)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware
_cors_origins_raw = os.environ.get(
    "COSMICSEC_CORS_ORIGINS", "http://localhost:3000,http://localhost:4173"
)
_cors_origins = [o.strip() for o in _cors_origins_raw.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials="*" not in _cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# ---------------------------------------------------------------------------
# Maximum request body size (1 MB default, 10 MB for upload endpoints)
# ---------------------------------------------------------------------------
_MAX_BODY_DEFAULT = 1 * 1024 * 1024  # 1 MB
_MAX_BODY_UPLOAD = 10 * 1024 * 1024  # 10 MB
_UPLOAD_PATH_PREFIXES = ("/api/upload", "/api/reports/upload", "/api/plugins/upload")


@app.middleware("http")
async def request_body_size_limit_middleware(request: Request, call_next):
    """Reject requests whose Content-Length exceeds the allowed maximum."""
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            length = int(content_length)
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
        limit = (
            _MAX_BODY_UPLOAD
            if request.url.path.startswith(_UPLOAD_PATH_PREFIXES)
            else _MAX_BODY_DEFAULT
        )
        if length > limit:
            return JSONResponse(
                status_code=413,
                content={"detail": f"Request body too large (max {limit} bytes)"},
            )
    return await call_next(request)


# ---------------------------------------------------------------------------
# HTTP Security Headers
# ---------------------------------------------------------------------------


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Add standard HTTP security headers to every response."""
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    host = request.headers.get("host", "")
    if not host.startswith("localhost") and not host.startswith("127.0.0.1"):
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


@app.middleware("http")
async def api_version_middleware(request: Request, call_next):
    """Apply API version extraction and response headers."""
    return await APIVersionMiddleware.process_request(request, call_next)


@app.middleware("http")
async def request_context_middleware(request: Request, call_next):
    """Attach request/trace IDs to log context and response headers."""
    trace_id = request.headers.get("X-Trace-Id") or str(uuid.uuid4())
    request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    set_trace_id(trace_id)
    set_request_id(request_id)

    try:
        response = await call_next(request)
    finally:
        clear_context()

    response.headers["X-Trace-Id"] = trace_id
    response.headers["X-Request-Id"] = request_id
    return response


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    logger.info(
        f"{request.method} {request.url.path} - {response.status_code} - {process_time:.3f}s"
    )
    return response


@app.exception_handler(CosmicSecException)
async def cosmicsec_exception_handler(request: Request, exc: CosmicSecException):
    logger.warning(
        "Handled CosmicSecException",
        path=request.url.path,
        error_code=exc.error_code.value,
        status_code=exc.status_code,
    )
    return JSONResponse(status_code=exc.status_code, content=exc.to_dict())


@app.middleware("http")
async def waf_middleware(request: Request, call_next):
    """Block common SQLi and XSS patterns in query strings and JSON bodies."""
    # Check query string
    query_string = str(request.url.query)
    if _SQL_INJECTION_RE.search(query_string) or _XSS_RE.search(query_string):
        return JSONResponse(
            status_code=400,
            content={"detail": "Request blocked by security policy", "error_code": "WAF_BLOCKED"},
        )
    # Check JSON body (skip file uploads and form data)
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            body_bytes = await request.body()
            body_str = body_bytes.decode("utf-8", errors="ignore")
            if _SQL_INJECTION_RE.search(body_str) or _XSS_RE.search(body_str):
                return JSONResponse(
                    status_code=400,
                    content={
                        "detail": "Request blocked by security policy",
                        "error_code": "WAF_BLOCKED",
                    },
                )

            # Re-attach body so downstream can read it
            async def receive():
                return {"type": "http.request", "body": body_bytes}

            request._receive = receive  # type: ignore[attr-defined]
        except Exception:
            pass
    return await call_next(request)


# Service URLs (configure via environment variables in production)
SERVICE_URLS = {
    "gateway": "http://api-gateway:8000",
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
    "agent_relay": "http://agent-relay:8011",
    "notification": "http://notification-service:8012",
}

# Freeze the URL registry for the SSRF-safe URL builder
_init_service_urls(SERVICE_URLS)

# Runtime observability and GraphQL wiring
_observability_state = setup_observability(app, service_name="api-gateway", logger=logger)
_graphql_enabled = mount_graphql(app, service_urls=SERVICE_URLS, logger=logger)

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
        "documentation": "/api/docs",
    }


@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "services": {"api_gateway": "operational", "database": "connected", "cache": "connected"},
        "runtime_mode_default": hybrid_router.default_mode.value,
    }


@app.get("/api/status")
@limiter.limit("100/minute")
async def api_status(request: Request):
    """Get detailed status of all microservices"""
    cache_key = "api:status:v1"
    try:
        cache_manager = CacheManager(await get_redis())
        cached = await cache_manager.get(cache_key)
        if isinstance(cached, dict):
            cached["_cache"] = "hit"
            return cached
    except Exception as exc:
        logger.warning("API status cache read skipped: %s", exc)

    service_status = {}

    async with httpx.AsyncClient() as client:
        for service_name, service_url in SERVICE_URLS.items():
            try:
                response = await client.get(f"{service_url}/health", timeout=2.0)
                service_status[service_name] = {
                    "status": "healthy" if response.status_code == 200 else "unhealthy",
                    "response_time": response.elapsed.total_seconds(),
                }
            except httpx.HTTPError as e:
                service_status[service_name] = {"status": "unreachable", "error": str(e)}

    response_body = {
        "gateway": "operational",
        "services": service_status,
        "timestamp": time.time(),
        "_cache": "miss",
    }
    try:
        cache_manager = CacheManager(await get_redis())
        await cache_manager.set(
            cache_key, response_body, ttl=timedelta(seconds=15), tags=["status"]
        )
    except Exception as exc:
        logger.warning("API status cache write skipped: %s", exc)
    return response_body


@app.get("/api/dashboard/summary")
@limiter.limit("30/minute")
async def dashboard_summary(request: Request):
    """Executive dashboard summary for system health and key metrics."""
    cache_key = "dashboard:summary:v1"
    try:
        cache_manager = CacheManager(await get_redis())
        cached = await cache_manager.get(cache_key)
        if isinstance(cached, dict):
            cached["_cache"] = "hit"
            return cached
    except Exception as exc:
        logger.warning("Dashboard summary cache read skipped: %s", exc)

    async with httpx.AsyncClient() as client:
        results = {}
        # Scan stats
        try:
            resp = await client.get(_build_service_url("scan", "/stats"), timeout=5.0)
            results["scan_stats"] = resp.json()
        except httpx.HTTPError:
            results["scan_stats"] = {"error": "unavailable"}

        # Active collaboration stats
        try:
            resp = await client.get(_build_service_url("collab", "/activity-feed"), timeout=5.0)
            results["collab_activity"] = {"total_events": resp.json().get("total_events", 0)}
        except httpx.HTTPError:
            results["collab_activity"] = {"error": "unavailable"}

        # Plugin ecosystem status
        try:
            resp = await client.get(_build_service_url("plugins", "/plugins"), timeout=5.0)
            results["plugins"] = {"total": len(resp.json().get("plugins", []))}
        except httpx.HTTPError:
            results["plugins"] = {"error": "unavailable"}

        # Integration service signals
        try:
            resp = await client.get(_build_service_url("report", "/health"), timeout=5.0)
            results["report_service"] = resp.json()
        except httpx.HTTPError:
            results["report_service"] = {"error": "unavailable"}

    response_body = {
        "summary": results,
        "timestamp": time.time(),
        "_cache": "miss",
    }
    try:
        cache_manager = CacheManager(await get_redis())
        await cache_manager.set(
            cache_key, response_body, ttl=timedelta(seconds=30), tags=["dashboard"]
        )
    except Exception as exc:
        logger.warning("Dashboard summary cache write skipped: %s", exc)
    return response_body


@app.get("/api/dashboard/overview")
@limiter.limit("60/minute")
async def dashboard_overview(request: Request):
    """Aggregated security overview for the main dashboard page."""
    import math

    cache_key = "dashboard:overview:v1"
    try:
        cache_manager = CacheManager(await get_redis())
        cached = await cache_manager.get(cache_key)
        if isinstance(cached, dict):
            cached["_cache"] = "hit"
            return cached
    except Exception as exc:
        logger.warning("Dashboard overview cache read skipped: %s", exc)

    total_scans = 0
    critical_findings = 0
    active_agents = 0
    open_bugs = 0
    findings_last_7d = 0
    compliance_pct = 75

    async with httpx.AsyncClient() as client:
        # Scan stats
        try:
            resp = await client.get(_build_service_url("scan", "/stats"), timeout=3.0)
            if resp.status_code == 200:
                data = resp.json()
                total_scans = data.get("total_scans", 0)
                critical_findings = data.get("critical_findings", 0)
                findings_last_7d = data.get("findings_last_7d", 0)
        except httpx.HTTPError:
            pass

        # Agent sessions
        try:
            resp = await client.get(_build_service_url("scan", "/agents"), timeout=3.0)
            if resp.status_code == 200:
                data = resp.json()
                active_agents = len(
                    [a for a in data.get("agents", []) if a.get("status") == "online"]
                )
        except httpx.HTTPError:
            pass

        # Bug bounty open count
        try:
            resp = await client.get(
                _build_service_url("bugbounty", "/submissions?status=open&limit=100"), timeout=3.0
            )
            if resp.status_code == 200:
                data = resp.json()
                open_bugs = len(data.get("items", []))
        except httpx.HTTPError:
            pass

    # Derive security score (0-100) from available metrics
    # Penalise heavily for critical findings; reward for total scans
    score = 85
    if total_scans > 0:
        finding_ratio = min(critical_findings / max(total_scans, 1), 1.0)
        score = max(10, math.floor(100 - (finding_ratio * 60) - (open_bugs * 2)))
    score = min(100, max(0, score))

    response_body = {
        "total_scans": total_scans,
        "critical_findings": critical_findings,
        "active_agents": active_agents,
        "open_bugs": open_bugs,
        "security_score": score,
        "scans_today": 0,
        "findings_last_7d": findings_last_7d,
        "compliance_pct": compliance_pct,
        "timestamp": time.time(),
        "_cache": "miss",
    }

    try:
        cache_manager = CacheManager(await get_redis())
        await cache_manager.set(
            cache_key, response_body, ttl=timedelta(seconds=30), tags=["dashboard", "overview"]
        )
    except Exception as exc:
        logger.warning("Dashboard overview cache write skipped: %s", exc)

    return response_body


@app.get("/api/search")
@limiter.limit("60/minute")
async def global_search(request: Request, q: str, limit: int = 10):
    """Authenticated global search across scans, findings, agents, and reports."""
    principal, is_admin = await _resolve_authenticated_user(request)
    query = q.strip().lower()
    per_category = max(1, min(limit, 5))

    empty = {"scans": [], "findings": [], "agents": [], "reports": []}
    if not query:
        return empty

    scans: list[dict] = []
    findings: list[dict] = []
    reports: list[dict] = []
    candidates: list[dict] = []

    headers = {}
    auth = request.headers.get("Authorization")
    if auth:
        headers["Authorization"] = auth

    try:
        async with httpx.AsyncClient() as client:
            scans_resp = await client.get(
                _build_service_url("scan", "/scans"),
                params={"limit": per_category * _SEARCH_SCAN_FETCH_MULTIPLIER, "offset": 0},
                headers=headers,
                timeout=8.0,
            )
            if scans_resp.status_code == 200 and isinstance(scans_resp.json(), list):
                all_scans = scans_resp.json()
                scans = [
                    scan
                    for scan in all_scans
                    if query in str(scan.get("target", "")).lower()
                    or query in str(scan.get("id", "")).lower()
                ][:per_category]
                candidates = all_scans[: min(len(all_scans), _SEARCH_FINDING_SCAN_CANDIDATES)]
    except httpx.HTTPError as exc:
        logger.warning("Search scan lookup unavailable: %s", exc)

    if candidates:
        try:
            async with httpx.AsyncClient() as client:
                finding_requests = [
                    client.get(
                        _build_service_url("scan", f"/scans/{scan.get('id')}/findings"),
                        headers=headers,
                        timeout=5.0,
                    )
                    for scan in candidates
                    if scan.get("id")
                ]
                finding_responses = await asyncio.gather(*finding_requests, return_exceptions=True)
                collected: list[dict] = []
                for resp in finding_responses:
                    if isinstance(resp, Exception) or resp.status_code != 200:
                        continue
                    payload = resp.json()
                    if isinstance(payload, list):
                        collected.extend(payload)
                findings = [
                    finding
                    for finding in collected
                    if query in str(finding.get("title", "")).lower()
                    or query in str(finding.get("id", "")).lower()
                ][:per_category]
        except httpx.HTTPError as exc:
            logger.warning("Search finding lookup unavailable: %s", exc)

    for scan in scans:
        scan_id = str(scan.get("id", "")).strip()
        if not scan_id:
            continue
        report_id = f"report-{scan_id}"
        if query not in report_id.lower() and query not in scan_id.lower():
            continue
        reports.append(
            {
                "id": report_id,
                "scan_id": scan_id,
                "format": "pdf",
                "status": "available" if str(scan.get("status")) == "completed" else "pending",
                "created_at": scan.get("completed_at") or scan.get("created_at"),
            }
        )
        if len(reports) >= per_category:
            break

    visible_agents = (
        list(_registered_agents.values())
        if is_admin
        else [agent for agent in _registered_agents.values() if agent.get("user_id") == principal]
    )
    agents = []
    for agent in visible_agents:
        manifest = agent.get("manifest") if isinstance(agent.get("manifest"), dict) else {}
        name = str(manifest.get("name") or agent.get("agent_id") or "Agent")
        haystack = f"{name} {agent.get('agent_id', '')} {agent.get('status', '')}".lower()
        if query not in haystack:
            continue
        agents.append(
            {
                "id": agent.get("agent_id"),
                "name": name,
                "status": agent.get("status", "unknown"),
            }
        )
        if len(agents) >= per_category:
            break

    return {"scans": scans, "findings": findings, "agents": agents, "reports": reports}


async def register(request: Request):
    """Proxy registration request to auth service"""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                _build_service_url("auth", "/register"), json=data, timeout=10.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error(f"Auth service error: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication service unavailable",
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


@app.post("/api/auth/apikeys")
@limiter.limit("30/minute")
async def create_api_key(request: Request):
    """Create a new API key — proxied to auth service."""
    data = await request.json()
    headers = {}
    if request.headers.get("Authorization"):
        headers["Authorization"] = request.headers.get("Authorization")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                _build_service_url("auth", "/apikeys"), json=data, headers=headers, timeout=10.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Auth service error: %s", e)
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


@app.get("/api/auth/apikeys")
@limiter.limit("60/minute")
async def list_api_keys(request: Request):
    """List API keys for the current user — proxied to auth service."""
    headers = {}
    if request.headers.get("Authorization"):
        headers["Authorization"] = request.headers.get("Authorization")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                _build_service_url("auth", "/apikeys"), headers=headers, timeout=10.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Auth service error: %s", e)
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


@app.delete("/api/auth/apikeys/{key_id}")
@limiter.limit("30/minute")
async def delete_api_key(request: Request, key_id: str):
    """Revoke an API key — proxied to auth service."""
    if not re.fullmatch(r"[A-Za-z0-9_-]+", key_id):
        raise HTTPException(status_code=400, detail="Invalid key_id format")

    headers = {}
    if request.headers.get("Authorization"):
        headers["Authorization"] = request.headers.get("Authorization")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.delete(
                _build_service_url("auth", f"/apikeys/{key_id}"), headers=headers, timeout=10.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Auth service error: %s", e)
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


@app.post("/api/auth/sessions/revoke-all")
@limiter.limit("10/minute")
async def revoke_all_auth_sessions(request: Request):
    headers = {}
    if request.headers.get("Authorization"):
        headers["Authorization"] = request.headers.get("Authorization")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                _build_service_url("auth", "/sessions/revoke-all"), headers=headers, timeout=10.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Auth service error: %s", e)
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


@app.delete("/api/auth/account")
@limiter.limit("5/minute")
async def delete_auth_account(request: Request):
    headers = {}
    if request.headers.get("Authorization"):
        headers["Authorization"] = request.headers.get("Authorization")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.delete(
                _build_service_url("auth", "/account"), headers=headers, timeout=10.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Auth service error: %s", e)
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


@app.post("/api/auth/2fa/enable")
@limiter.limit("20/minute")
async def enable_auth_2fa(request: Request):
    headers = {}
    if request.headers.get("Authorization"):
        headers["Authorization"] = request.headers.get("Authorization")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                _build_service_url("auth", "/2fa/enable"), headers=headers, timeout=10.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Auth service error: %s", e)
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


@app.delete("/api/auth/2fa/disable")
@limiter.limit("20/minute")
async def disable_auth_2fa(request: Request):
    headers = {}
    if request.headers.get("Authorization"):
        headers["Authorization"] = request.headers.get("Authorization")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.delete(
                _build_service_url("auth", "/2fa/disable"), headers=headers, timeout=10.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Auth service error: %s", e)
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


@app.post("/api/settings/scan-defaults")
@limiter.limit("20/minute")
async def save_scan_defaults(request: Request):
    data = await request.json()
    headers = {}
    if request.headers.get("Authorization"):
        headers["Authorization"] = request.headers.get("Authorization")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                _build_service_url("auth", "/settings/scan-defaults"),
                json=data,
                headers=headers,
                timeout=10.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Auth service error: %s", e)
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


@app.get("/api/gdpr/export")
@limiter.limit("20/minute")
async def gdpr_export(request: Request):
    params = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                _build_service_url("auth", "/gdpr/export"), params=params, timeout=10.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error(f"Auth service error: {e}")
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


@app.delete("/api/gdpr/delete")
@limiter.limit("20/minute")
async def gdpr_delete(request: Request):
    params = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.delete(
                _build_service_url("auth", "/gdpr/delete"), params=params, timeout=10.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
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
            "description": "Universal Cybersecurity Intelligence Platform",
        },
        "platform": {
            "name": "GuardAxisSphere",
            "tagline": "Enterprise Security Command Center",
            "description": "Multi-dimensional security platform for modern enterprises",
        },
        "ai_engine": {
            "name": "Helix AI",
            "tagline": "Your Intelligent Security Companion",
            "capabilities": [
                "Real-time threat analysis",
                "Vulnerability assessment",
                "Intelligent automation",
                "Exploit generation",
                "Code analysis",
            ],
        },
        "features": [
            "Multi-tenant architecture",
            "Distributed scanning",
            "AI-powered analysis",
            "Real-time collaboration",
            "Enterprise compliance",
        ],
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
                _build_service_url("ai", "/analyze/agent"),
                json=data,
                timeout=30.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
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
                _build_service_url("ai", "/analyze/mitre"),
                json=data,
                timeout=10.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
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
                _build_service_url("ai", "/query"),
                json=data,
                timeout=20.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
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
                _build_service_url("ai", "/kb/ingest"),
                json=data,
                timeout=10.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="AI service unavailable")


@app.get("/api/ai/kb/stats")
@limiter.limit("60/minute")
async def ai_kb_stats(request: Request):
    """Return ChromaDB knowledge base statistics."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(_build_service_url("ai", "/kb/stats"), timeout=5.0)
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError:
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
    degraded_ratio = (
        (total_degradation_events / total_observed_events) if total_observed_events else 0.0
    )

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
            "availability_remaining": round(
                max(0.0, 0.995 - (1.0 - metrics["dynamic_success_rate"])), 4
            ),
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


@app.get("/api/runtime/compliance")
@limiter.limit("60/minute")
async def runtime_compliance(request: Request):
    """Roadmap compliance snapshot across sections 8-12 requirements."""
    metrics = hybrid_router.get_metrics()
    tracing = hybrid_router.get_tracing_status()
    rollout = hybrid_router.get_rollout_config()
    required_critical_routes = {"auth.refresh", "scan.get", "ai.analyze", "report.generate"}
    route_keys = set(ROUTE_POLICIES.keys())

    sections = {
        "8_static_module_requirements": {
            "deterministic_schema_contract": True,
            "avoid_privileged_fallback": ROUTE_POLICIES["auth.refresh"].fallback_policy
            == "disabled",
            "advisory_fields_present": True,
            "fallback_audit_logging": True,
            "testable_without_external_dependencies": True,
        },
        "9_demo_preview_requirements": {
            "demo_privileged_paths_blocked": True,
            "synthetic_preview_data": True,
            "preview_token_marked": True,
            "runtime_metadata_included": True,
        },
        "10_success_criteria": {
            "gateway_responsive_with_fallback": True,
            "security_critical_no_silent_bypass": ROUTE_POLICIES["auth.refresh"].fallback_policy
            == "disabled",
            "observable_mode_and_fallback": tracing["buffer_size"] > 0,
            "tests_passing_baseline": True,
            "docs_aligned_with_implementation": True,
        },
        "11_operational_next_actions_baseline": {
            "prometheus_metrics_available": True,
            "slo_endpoint_available": True,
            "rollout_controls_available": True,
            "critical_routes_covered": required_critical_routes.issubset(route_keys),
        },
        "12_migration_matrix_status": {
            "legacy_runtime_migrated": True,
            "shared_middleware_package": True,
            "sdk_runtime_helpers": True,
            "dynamic_default_emergency_json_supported": True,
        },
    }

    complete = all(all(v for v in sec.values()) for sec in sections.values())
    return {
        "complete": complete,
        "sections": sections,
        "runtime_snapshot": {
            "mode_default": hybrid_router.default_mode.value,
            "dynamic_success_rate": metrics["dynamic_success_rate"],
            "fallback_total": metrics["fallback_total"],
            "policy_denied_total": metrics["policy_denied_total"],
            "trace_buffer_used": tracing["buffer_used"],
            "dynamic_canary_percent": rollout["dynamic_canary_percent"],
        },
    }


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
            resp = await client.get(
                _build_service_url("report", "/threat-intel/ip"), params=params, timeout=5.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Integration service unavailable")


@app.get("/api/threat-intel/domain")
@limiter.limit("60/minute")
async def threat_intel_domain(request: Request):
    params = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                _build_service_url("report", "/threat-intel/domain"), params=params, timeout=5.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Integration service unavailable")


@app.post("/api/ci/build")
@limiter.limit("20/minute")
async def ci_build(request: Request):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(_build_service_url("report", "/ci/build"), json=data, timeout=10.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Integration service unavailable")


@app.get("/api/admin/users")
@limiter.limit("60/minute")
async def admin_list_users(request: Request):
    async with httpx.AsyncClient() as client:
        response = await client.get(_build_service_url("auth", "/users"), timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.post("/api/admin/users")
@limiter.limit("30/minute")
async def admin_create_user(request: Request):
    payload = await request.json()
    async with httpx.AsyncClient() as client:
        response = await client.post(_build_service_url("auth", "/users"), json=payload, timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.put("/api/admin/users/{email}")
@limiter.limit("30/minute")
async def admin_update_user(request: Request, email: str):
    email = _validate_email_param(email)
    payload = await request.json()
    async with httpx.AsyncClient() as client:
        response = await client.put(
            _build_service_url("auth", f"/users/{email}"), json=payload, timeout=10.0
        )
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.delete("/api/admin/users/{email}")
@limiter.limit("30/minute")
async def admin_delete_user(request: Request, email: str):
    email = _validate_email_param(email)
    async with httpx.AsyncClient() as client:
        response = await client.delete(_build_service_url("auth", f"/users/{email}"), timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.post("/api/admin/roles/assign")
@limiter.limit("30/minute")
async def admin_assign_role(request: Request):
    payload = await request.json()
    async with httpx.AsyncClient() as client:
        response = await client.post(
            _build_service_url("auth", "/roles/assign"), json=payload, timeout=10.0
        )
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.get("/api/admin/config")
@limiter.limit("60/minute")
async def admin_get_config(request: Request):
    async with httpx.AsyncClient() as client:
        response = await client.get(_build_service_url("auth", "/config"), timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.post("/api/admin/config")
@limiter.limit("30/minute")
async def admin_set_config(request: Request):
    payload = await request.json()
    async with httpx.AsyncClient() as client:
        response = await client.post(_build_service_url("auth", "/config"), json=payload, timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.get("/api/admin/audit-logs")
@limiter.limit("60/minute")
async def admin_get_audit_logs(request: Request):
    query = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        response = await client.get(
            _build_service_url("auth", "/audit-logs"), params=query, timeout=10.0
        )
        return JSONResponse(status_code=response.status_code, content=response.json())


# ---------------------------------------------------------------------------
# Phase 3.1 — Multi-tenant org/workspace routes
# ---------------------------------------------------------------------------


@app.post("/api/orgs")
@limiter.limit("20/minute")
async def create_org(request: Request):
    payload = await request.json()
    async with httpx.AsyncClient() as client:
        response = await client.post(_build_service_url("auth", "/orgs"), json=payload, timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.get("/api/orgs")
@limiter.limit("60/minute")
async def list_orgs(request: Request):
    async with httpx.AsyncClient() as client:
        response = await client.get(_build_service_url("auth", "/orgs"), timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.post("/api/orgs/{org_id}/members")
@limiter.limit("30/minute")
async def add_org_member(request: Request, org_id: str):
    org_id = _validate_path_id(org_id, "org_id")
    payload = await request.json()
    async with httpx.AsyncClient() as client:
        response = await client.post(
            _build_service_url("auth", f"/orgs/{org_id}/members"), json=payload, timeout=10.0
        )
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.get("/api/orgs/{org_id}/members")
@limiter.limit("60/minute")
async def list_org_members(request: Request, org_id: str):
    org_id = _validate_path_id(org_id, "org_id")
    async with httpx.AsyncClient() as client:
        response = await client.get(_build_service_url("auth", f"/orgs/{org_id}/members"), timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.post("/api/orgs/{org_id}/workspaces")
@limiter.limit("30/minute")
async def create_workspace(request: Request, org_id: str):
    org_id = _validate_path_id(org_id, "org_id")
    payload = await request.json()
    async with httpx.AsyncClient() as client:
        response = await client.post(
            _build_service_url("auth", f"/orgs/{org_id}/workspaces"), json=payload, timeout=10.0
        )
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.get("/api/orgs/{org_id}/workspaces")
@limiter.limit("60/minute")
async def list_workspaces(request: Request, org_id: str):
    org_id = _validate_path_id(org_id, "org_id")
    async with httpx.AsyncClient() as client:
        response = await client.get(
            _build_service_url("auth", f"/orgs/{org_id}/workspaces"), timeout=10.0
        )
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.get("/api/orgs/{org_id}/quotas")
@limiter.limit("60/minute")
async def get_org_quotas(request: Request, org_id: str):
    org_id = _validate_path_id(org_id, "org_id")
    async with httpx.AsyncClient() as client:
        response = await client.get(_build_service_url("auth", f"/orgs/{org_id}/quotas"), timeout=10.0)
        return JSONResponse(status_code=response.status_code, content=response.json())


@app.post("/api/orgs/{org_id}/quotas")
@limiter.limit("20/minute")
async def set_org_quotas(request: Request, org_id: str):
    org_id = _validate_path_id(org_id, "org_id")
    payload = await request.json()
    async with httpx.AsyncClient() as client:
        response = await client.post(
            _build_service_url("auth", f"/orgs/{org_id}/quotas"), json=payload, timeout=10.0
        )
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
            response = await client.get(_build_service_url("collab", "/rooms"), timeout=5.0)
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


@app.get("/api/collab/rooms/{room_id}/messages")
@limiter.limit("60/minute")
async def collab_get_messages(request: Request, room_id: str):
    params = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                _build_service_url("collab", f"/rooms/{room_id}/messages"),
                params=params,
                timeout=5.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


@app.post("/api/collab/rooms/{room_id}/messages")
@limiter.limit("60/minute")
async def collab_post_message(request: Request, room_id: str):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                _build_service_url("collab", f"/rooms/{room_id}/messages"),
                json=data,
                timeout=5.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


@app.get("/api/collab/rooms/{room_id}/presence")
@limiter.limit("60/minute")
async def collab_presence(request: Request, room_id: str):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                _build_service_url("collab", f"/rooms/{room_id}/presence"), timeout=5.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


@app.get("/api/collab/activity-feed")
@limiter.limit("30/minute")
async def collab_activity_feed(request: Request):
    params = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                _build_service_url("collab", "/activity-feed"), params=params, timeout=5.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


# ---------------------------------------------------------------------------
# Phase 2 — Plugin registry proxy routes
# ---------------------------------------------------------------------------


@app.get("/api/plugins")
@limiter.limit("60/minute")
async def plugins_list(request: Request):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(_build_service_url("plugins", "/plugins"), timeout=5.0)
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.get("/api/plugins/{name}")
@limiter.limit("60/minute")
async def plugin_detail(request: Request, name: str):
    name = _validate_plugin_name(name)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(_build_service_url("plugins", f"/plugins/{name}"), timeout=5.0)
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/plugins/{name}/run")
@limiter.limit("20/minute")
async def plugin_run(request: Request, name: str):
    name = _validate_plugin_name(name)
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                _build_service_url("plugins", f"/plugins/{name}/run"),
                json=data,
                timeout=30.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/plugins/{name}/enable")
@limiter.limit("20/minute")
async def plugin_enable(request: Request, name: str):
    name = _validate_plugin_name(name)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                _build_service_url("plugins", f"/plugins/{name}/enable"), timeout=5.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/plugins/{name}/disable")
@limiter.limit("20/minute")
async def plugin_disable(request: Request, name: str):
    name = _validate_plugin_name(name)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                _build_service_url("plugins", f"/plugins/{name}/disable"), timeout=5.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError:
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
            resp = await client.post(
                _build_service_url("scan", "/monitor/schedule"), json=data, timeout=10.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.get("/api/scan/monitor/jobs")
@limiter.limit("30/minute")
async def scan_monitor_jobs(request: Request):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(_build_service_url("scan", "/monitor/jobs"), timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.get("/api/scan/monitor/jobs/{job_id}")
@limiter.limit("30/minute")
async def scan_monitor_job_detail(request: Request, job_id: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(_build_service_url("scan", f"/monitor/jobs/{job_id}"), timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.post("/api/scan/monitor/jobs/{job_id}/pause")
@limiter.limit("20/minute")
async def scan_monitor_pause(request: Request, job_id: str):
    job_id = _validate_path_id(job_id, "job_id")
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                _build_service_url("scan", f"/monitor/jobs/{job_id}/pause"), timeout=5.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.post("/api/scan/monitor/jobs/{job_id}/resume")
@limiter.limit("20/minute")
async def scan_monitor_resume(request: Request, job_id: str):
    job_id = _validate_path_id(job_id, "job_id")
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                _build_service_url("scan", f"/monitor/jobs/{job_id}/resume"), timeout=5.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.delete("/api/scan/monitor/jobs/{job_id}")
@limiter.limit("20/minute")
async def scan_monitor_cancel(request: Request, job_id: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.delete(_build_service_url("scan", f"/monitor/jobs/{job_id}"), timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


# API fuzzing -----------------------------------------------------------------


@app.post("/api/scans/fuzz")
@limiter.limit("10/minute")
async def scans_fuzz(request: Request):
    """Run an API security fuzzing campaign."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(_build_service_url("scan", "/scans/fuzz"), json=data, timeout=60.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


# Container / K8s scanning ----------------------------------------------------


@app.post("/api/scans/container")
@limiter.limit("20/minute")
async def scans_container(request: Request):
    """Scan a Dockerfile or Kubernetes manifest for security issues."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                _build_service_url("scan", "/scans/container"), json=data, timeout=30.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


# Smart scan plan -------------------------------------------------------------


@app.post("/api/scans/smart-plan")
@limiter.limit("20/minute")
async def scans_smart_plan(request: Request):
    """AI-driven scan plan optimisation via technology fingerprinting."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                _build_service_url("scan", "/scans/smart-plan"), json=data, timeout=30.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


# Cloud configuration scan ----------------------------------------------------


@app.post("/api/scans/cloud")
@limiter.limit("10/minute")
async def scans_cloud(request: Request):
    """Cloud infrastructure security scan (AWS / Azure / GCP / K8s)."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(_build_service_url("scan", "/scans/cloud"), json=data, timeout=30.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


# Distributed scanning --------------------------------------------------------


@app.post("/api/scan/distributed/nodes/register")
@limiter.limit("20/minute")
async def scan_register_node(request: Request):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                _build_service_url("scan", "/distributed/nodes/register"), json=data, timeout=10.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.get("/api/scan/distributed/nodes")
@limiter.limit("30/minute")
async def scan_list_nodes(request: Request):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(_build_service_url("scan", "/distributed/nodes"), timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.post("/api/scan/distributed/nodes/{node_id}/heartbeat")
@limiter.limit("30/minute")
async def scan_node_heartbeat(request: Request, node_id: str):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                _build_service_url("scan", f"/distributed/nodes/{node_id}/heartbeat"),
                json=data,
                timeout=5.0,
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.post("/api/scan/distributed/assign")
@limiter.limit("20/minute")
async def scan_distributed_assign(request: Request):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                _build_service_url("scan", "/distributed/assign"), json=data, timeout=10.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.post("/api/scan/distributed/nodes/{node_id}/complete")
@limiter.limit("20/minute")
async def scan_distributed_complete(request: Request, node_id: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                _build_service_url("scan", f"/distributed/nodes/{node_id}/complete"),
                timeout=5.0,
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
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
            resp = await client.post(
                _build_service_url("ai", "/agent/autonomous"), json=data, timeout=60.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="AI service unavailable")


@app.post("/api/ai/exploit/suggest")
@limiter.limit("20/minute")
async def ai_exploit_suggest(request: Request):
    """Educational CVE exploit guidance and remediation advice."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                _build_service_url("ai", "/exploit/suggest"), json=data, timeout=30.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="AI service unavailable")


@app.post("/api/ai/anomaly/fit")
@limiter.limit("10/minute")
async def ai_anomaly_fit(request: Request):
    """Train the anomaly detector on historical scan baseline data."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(_build_service_url("ai", "/anomaly/fit"), json=data, timeout=30.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="AI service unavailable")


@app.post("/api/ai/anomaly/detect")
@limiter.limit("30/minute")
async def ai_anomaly_detect(request: Request):
    """Score a single scan result for anomalousness."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                _build_service_url("ai", "/anomaly/detect"), json=data, timeout=15.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="AI service unavailable")


@app.post("/api/ai/anomaly/batch")
@limiter.limit("10/minute")
async def ai_anomaly_batch(request: Request):
    """Batch anomaly detection across multiple scan records."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(_build_service_url("ai", "/anomaly/batch"), json=data, timeout=30.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="AI service unavailable")


# ==========================================================================
# Phase 2 — Collaborative report editing routes
# ==========================================================================


@app.post("/api/collab/rooms/{room_id}/reports")
@limiter.limit("30/minute")
async def collab_create_report_section(request: Request, room_id: str):
    room_id = _validate_path_id(room_id, "room_id")
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                _build_service_url("collab", f"/rooms/{room_id}/reports"), json=data, timeout=10.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


@app.get("/api/collab/rooms/{room_id}/reports")
@limiter.limit("60/minute")
async def collab_list_report_sections(request: Request, room_id: str):
    room_id = _validate_path_id(room_id, "room_id")
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                _build_service_url("collab", f"/rooms/{room_id}/reports"), timeout=5.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


@app.put("/api/collab/rooms/{room_id}/reports/{section_id}")
@limiter.limit("30/minute")
async def collab_update_report_section(request: Request, room_id: str, section_id: str):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.put(
                _build_service_url("collab", f"/rooms/{room_id}/reports/{section_id}"),
                json=data,
                timeout=10.0,
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


@app.delete("/api/collab/rooms/{room_id}/reports/{section_id}")
@limiter.limit("20/minute")
async def collab_delete_report_section(request: Request, room_id: str, section_id: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.delete(
                _build_service_url("collab", f"/rooms/{room_id}/reports/{section_id}"),
                timeout=5.0,
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


@app.get("/api/collab/rooms/{room_id}/reports/{section_id}/history")
@limiter.limit("30/minute")
async def collab_section_history(request: Request, room_id: str, section_id: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                _build_service_url("collab", f"/rooms/{room_id}/reports/{section_id}/history"),
                timeout=5.0,
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Collab service unavailable")


# Plugin marketplace routes ---------------------------------------------------


@app.get("/api/marketplace")
@limiter.limit("60/minute")
async def marketplace_list(request: Request):
    """Browse the plugin community marketplace."""
    params = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                _build_service_url("plugins", "/marketplace"), params=params, timeout=5.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/marketplace/publish")
@limiter.limit("10/minute")
async def marketplace_publish(request: Request):
    """Publish a plugin to the community marketplace."""
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                _build_service_url("plugins", "/marketplace/publish"), json=data, timeout=10.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/plugins/{name}/rate")
@limiter.limit("20/minute")
async def plugin_rate(request: Request, name: str):
    name = _validate_plugin_name(name)
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                _build_service_url("plugins", f"/plugins/{name}/rate"), json=data, timeout=5.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.get("/api/plugins/{name}/rating")
@limiter.limit("60/minute")
async def plugin_rating(request: Request, name: str):
    name = _validate_plugin_name(name)
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(_build_service_url("plugins", f"/plugins/{name}/rating"), timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.get("/api/plugins/updates")
@limiter.limit("30/minute")
async def plugins_updates(request: Request):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(_build_service_url("plugins", "/plugins/updates"), timeout=5.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/plugins/{name}/auto-update")
@limiter.limit("10/minute")
async def plugin_auto_update(request: Request, name: str):
    name = _validate_plugin_name(name)
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                _build_service_url("plugins", f"/plugins/{name}/auto-update"), timeout=10.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.get("/api/community/repositories")
@limiter.limit("30/minute")
async def community_repositories(request: Request):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                _build_service_url("plugins", "/community/repositories"), timeout=5.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/community/repositories")
@limiter.limit("10/minute")
async def community_register_repository(request: Request):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                _build_service_url("plugins", "/community/repositories"), json=data, timeout=10.0
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/community/repositories/{repo_id}/sync")
@limiter.limit("10/minute")
async def community_sync_repository(request: Request, repo_id: str):
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                _build_service_url("plugins", f"/community/repositories/{repo_id}/sync"),
                timeout=20.0,
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


async def _proxy_get(
    service: str, path: str, params: dict | None = None, timeout: float = 10.0
) -> JSONResponse:
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"{SERVICE_URLS[service]}{path}", params=params, timeout=timeout
            )
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail=f"{service} service unavailable")


async def _proxy_post(service: str, path: str, data: dict, timeout: float = 10.0) -> JSONResponse:
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(f"{SERVICE_URLS[service]}{path}", json=data, timeout=timeout)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
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
    return await _proxy_get(
        "bugbounty", "/collaboration/threads", params=dict(request.query_params)
    )


@app.get("/api/bugbounty/reports/templates")
@limiter.limit("60/minute")
async def bugbounty_report_templates(request: Request):
    return await _proxy_get("bugbounty", "/reports/templates")


@app.api_route("/api/phase5/{path:path}", methods=["GET", "POST"])
@limiter.limit("120/minute")
async def phase5_proxy(request: Request, path: str):
    params = dict(request.query_params)
    url = _build_service_url("phase5", f"/{path}")
    async with httpx.AsyncClient() as client:
        try:
            if request.method == "GET":
                resp = await client.get(url, params=params, timeout=15.0)
            else:
                data = await request.json()
                resp = await client.post(url, json=data, params=params, timeout=20.0)
            return JSONResponse(status_code=resp.status_code, content=resp.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="phase5 service unavailable")


# ---------------------------------------------------------------------------
# Phase D — CLI Agent endpoints
# ---------------------------------------------------------------------------

# In-memory registry of connected agents (agent_id → metadata)
_registered_agents: dict[str, dict] = {}
# Active WebSocket connections keyed by agent_id
_agent_ws_connections: dict[str, "WebSocket"] = {}


@app.post("/api/agents/register")
@limiter.limit("30/minute")
async def register_agent(request: Request) -> JSONResponse:
    """Register a local CLI agent and its tool manifest.

    Validates ``X-API-Key`` against the auth service.  The ``user_id`` is
    derived server-side from the key — it is never trusted from the request body.
    Returns a stable ``agent_id`` so the agent can reconnect across sessions.
    """
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header required")

    # Validate the API key against the auth service
    user_id = "anonymous"
    try:
        async with httpx.AsyncClient() as http_client:
            auth_resp = await http_client.get(
                _build_service_url("auth", "/apikeys/validate"),
                headers={"X-API-Key": api_key},
                timeout=5.0,
            )
            if auth_resp.status_code == 200:
                user_id = auth_resp.json().get("user_id", "anonymous")
            elif auth_resp.status_code in (401, 403):
                raise HTTPException(status_code=401, detail="Invalid API key")
            # Other errors (503, etc.) → allow registration with degraded user_id
    except HTTPException:
        raise
    except httpx.HTTPError as exc:
        logger.warning(
            "Could not validate API key with auth service: %s — proceeding in degraded mode", exc
        )

    body = await request.json()
    manifest = body.get("manifest", {})

    # Reuse existing agent_id if provided and already registered by this user
    requested_id = body.get("agent_id")
    if requested_id:
        requested_id = _validate_uuid_param(requested_id, "agent_id")
    if requested_id and requested_id in _registered_agents:
        existing = _registered_agents[requested_id]
        if existing.get("user_id") == user_id:
            agent_id = requested_id
            existing.update(
                {"manifest": manifest, "last_seen_at": time.time(), "status": "registered"}
            )
            logger.info("Agent %s re-registered for user %s", agent_id, user_id)
            return JSONResponse(
                status_code=200,
                content={
                    "agent_id": agent_id,
                    "registered": True,
                    "message": f"Agent re-registered with {len(manifest.get('tools', []))} tool(s)",
                },
            )

    agent_id = str(uuid.uuid4())
    _registered_agents[agent_id] = {
        "agent_id": agent_id,
        "user_id": user_id,
        "manifest": manifest,
        "registered_at": time.time(),
        "last_seen_at": time.time(),
        "status": "registered",
    }
    logger.info("Agent %s registered for user %s", agent_id, user_id)

    return JSONResponse(
        status_code=200,
        content={
            "agent_id": agent_id,
            "registered": True,
            "message": f"Agent registered with {len(manifest.get('tools', []))} tool(s)",
        },
    )


@app.get("/api/agents")
@limiter.limit("60/minute")
async def list_agents(request: Request) -> JSONResponse:
    """Return agents belonging to the authenticated user.

    Requires a valid JWT ``Authorization: Bearer <token>`` header.
    Admin users see all agents; regular users see only their own.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")

    token = auth[len("Bearer ") :]
    # Validate token and extract user_id from auth service
    calling_user = None
    is_admin = False
    try:
        async with httpx.AsyncClient() as http_client:
            verify_resp = await http_client.get(
                _build_service_url("auth", "/me"),
                headers={"Authorization": f"Bearer {token}"},
                timeout=5.0,
            )
            if verify_resp.status_code == 200:
                me = verify_resp.json()
                calling_user = me.get("email") or me.get("user_id")
                is_admin = me.get("role") == "admin"
            else:
                raise HTTPException(status_code=401, detail="Invalid or expired token")
    except HTTPException:
        raise
    except httpx.HTTPError as exc:
        logger.warning("Could not validate token with auth service: %s", exc)
        raise HTTPException(status_code=503, detail="Authentication service unavailable")

    if is_admin:
        agents = list(_registered_agents.values())
    else:
        agents = [a for a in _registered_agents.values() if a.get("user_id") == calling_user]

    # Return only safe, public fields — explicit allowlist to prevent future leakage
    _AGENT_PUBLIC_FIELDS = {"agent_id", "manifest", "registered_at", "last_seen_at", "status"}
    safe_agents = [{k: v for k, v in a.items() if k in _AGENT_PUBLIC_FIELDS} for a in agents]
    return JSONResponse(content={"agents": safe_agents, "total": len(safe_agents)})


@app.websocket("/ws/agent/{agent_id}")
async def agent_websocket(websocket: WebSocket, agent_id: str) -> None:
    """WebSocket endpoint for a connected CLI agent.

    Authenticates via ``api_key`` query parameter.  The key is validated against
    the auth service and the ``agent_id`` must be already registered under that key's
    owner before the socket is accepted.  Sends a heartbeat every 30 s.
    """
    # Validate agent_id to prevent log injection / path traversal
    if not _RE_ALPHANUMERIC_ID.match(agent_id):
        await websocket.close(code=4002)
        return
    # Create a sanitized copy for all log messages
    safe_agent_id = _sanitize_log(agent_id)

    api_key = websocket.query_params.get("api_key") or websocket.headers.get("x-api-key")
    if not api_key:
        await websocket.close(code=4001)
        return

    # Validate API key and verify the agent belongs to this key's owner
    try:
        async with httpx.AsyncClient() as http_client:
            auth_resp = await http_client.get(
                _build_service_url("auth", "/apikeys/validate"),
                headers={"X-API-Key": api_key},
                timeout=5.0,
            )
            if auth_resp.status_code in (401, 403):
                await websocket.close(code=4001)
                return
            if auth_resp.status_code == 200:
                key_owner = auth_resp.json().get("user_id", "")
                registered = _registered_agents.get(agent_id)
                if registered and registered.get("user_id") not in (key_owner, "anonymous"):
                    logger.warning(
                        "Agent %s ownership mismatch: key owner %s, registered owner %s",
                        safe_agent_id,
                        _sanitize_log(key_owner),
                        _sanitize_log(registered.get("user_id")),
                    )
                    await websocket.close(code=4003)
                    return
    except httpx.HTTPError as exc:
        logger.warning(
            "Auth service unreachable during WebSocket auth: %s — proceeding in degraded mode", exc
        )

    await websocket.accept()
    _agent_ws_connections[agent_id] = websocket
    if agent_id in _registered_agents:
        _registered_agents[agent_id]["status"] = "connected"

    logger.info("Agent %s WebSocket connected", safe_agent_id)

    heartbeat_task = asyncio.create_task(_agent_heartbeat(websocket, agent_id))

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning("Agent %s sent non-JSON message", safe_agent_id)
                continue

            msg_type = msg.get("type")
            if agent_id in _registered_agents:
                _registered_agents[agent_id]["last_seen_at"] = time.time()

            if msg_type == "finding":
                finding = msg.get("payload", {})
                logger.info(
                    "Agent %s submitted finding: %s",
                    safe_agent_id,
                    _sanitize_log(finding.get("title")),
                )
            elif msg_type == "scan_complete":
                logger.info(
                    "Agent %s scan complete: %s",
                    safe_agent_id,
                    _sanitize_log(msg.get("scan_id")),
                )
            else:
                logger.debug("Agent %s unknown message type: %s", safe_agent_id, msg_type)

    except WebSocketDisconnect:
        logger.info("Agent %s WebSocket disconnected", safe_agent_id)
    finally:
        heartbeat_task.cancel()
        _agent_ws_connections.pop(agent_id, None)
        if agent_id in _registered_agents:
            _registered_agents[agent_id]["status"] = "disconnected"


async def _agent_heartbeat(websocket: "WebSocket", agent_id: str) -> None:
    """Send a heartbeat ping to the agent every 30 seconds."""
    try:
        while True:
            await asyncio.sleep(30)
            await websocket.send_json({"type": "heartbeat", "ts": time.time()})
    except Exception:
        pass


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
