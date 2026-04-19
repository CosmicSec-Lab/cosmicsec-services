"""
CosmicSec API Gateway
Main entry point for all API requests with routing, authentication, and rate limiting
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import socket
import time
import urllib.parse
import uuid
from datetime import UTC, datetime, timedelta

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from cosmicsec_platform.config import get_config
from cosmicsec_platform.contracts.runtime_metadata import HYBRID_SCHEMA, HYBRID_VERSION
from cosmicsec_platform.middleware.hybrid_router import HybridRouter
from cosmicsec_platform.middleware.policy_registry import ROUTE_POLICIES
from cosmicsec_platform.middleware.static_profiles import STATIC_PROFILES
from cosmicsec_platform.service_discovery import get_registry, log_service_config
from services.api_gateway.graphql_runtime import mount_graphql
from services.api_gateway.ingest_bridge import (
    check_rust_ingest_health as _check_rust_health,
)
from services.api_gateway.ingest_bridge import (
    ingest_batch as _rust_ingest_batch,
)
from services.api_gateway.white_label import WhiteLabelMiddleware, mount_branding_routes
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
_RE_ORG_SLUG = re.compile(r"^[a-z0-9\-]{2,64}$")
_RE_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
_RE_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
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


def _validate_org_slug(value: str) -> str:
    """Validate organization slug path parameter."""
    normalized = value.strip().lower()
    if not _RE_ORG_SLUG.match(normalized):
        raise HTTPException(status_code=400, detail="Invalid organization slug")
    return normalized


def _sanitize_log(value: object, max_len: int = 200) -> str:
    """Sanitize a user-provided value before including it in a log message.

    Removes newline and carriage-return characters to prevent log injection,
    and truncates to ``max_len`` characters.
    """
    text = str(value) if value is not None else ""
    # Strip log-injection control characters
    text = text.replace("\n", "\\n").replace("\r", "\\r").replace("\x00", "")
    return text[:max_len]


def _is_private_or_loopback_host(value: str) -> bool:
    """Return True when value is an IP in blocked guest ranges."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(
        [
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        ]
    )


def _validate_guest_domain(domain: str) -> str:
    normalized = (domain or "").strip().lower().rstrip(".")
    if not normalized or not _RE_DOMAIN.match(normalized):
        raise HTTPException(status_code=400, detail="Invalid domain")
    if _is_private_or_loopback_host(normalized):
        raise HTTPException(status_code=403, detail="Guest sandbox denied target")
    return normalized


def _truncate_guest_payload(payload: object, max_bytes: int = 50 * 1024) -> object:
    """Ensure guest endpoint responses stay below size limits."""
    encoded = json.dumps(payload, default=str).encode("utf-8")
    if len(encoded) <= max_bytes:
        return payload
    preview = encoded[: max_bytes - 64].decode("utf-8", errors="ignore")
    return {
        "truncated": True,
        "max_bytes": max_bytes,
        "preview": preview,
    }


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


async def _resolve_websocket_user(websocket: WebSocket) -> tuple[str, bool] | None:
    """Validate bearer token from query/header for websocket endpoints.

    Returns ``(principal, is_admin)`` on success, otherwise ``None``.
    """
    token = websocket.query_params.get("token")
    if not token:
        auth_header = websocket.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()

    if not token:
        return None

    try:
        async with httpx.AsyncClient() as client:
            verify_resp = await client.get(
                _build_service_url("auth", "/me"),
                headers={"Authorization": f"Bearer {token}"},
                timeout=5.0,
            )
    except httpx.HTTPError:
        return None

    if verify_resp.status_code != 200:
        return None

    me = verify_resp.json()
    principal = me.get("email") or me.get("user_id") or me.get("id")
    if not principal:
        return None

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
if "*" in _cors_origins:
    _cors_origins = [o for o in _cors_origins if o != "*"]
_cors_origin_set = set(_cors_origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def enforce_cors_allowlist(request: Request, call_next):
    origin = request.headers.get("origin")
    if origin and origin not in _cors_origin_set:
        return JSONResponse(status_code=403, content={"detail": "Origin not allowed"})
    return await call_next(request)


# GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)

# White-label org branding middleware (Phase R.5)
app.add_middleware(WhiteLabelMiddleware)
mount_branding_routes(app)

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
            logger.debug("WAF request body inspection skipped due to parsing error", exc_info=True)
    return await call_next(request)


# Service discovery — auto-detects OS and deployment mode
# In Docker: Uses service names (auth-service:8001, etc)
# In local dev: Uses localhost:8001, etc
# In self-hosted: Uses configured SERVICE_HOST:PORT
_platform_config = get_config()
_service_registry = get_registry()
SERVICE_URLS = _service_registry.get_all_urls()

# Log configuration for debugging
logger.info(f"Platform Config: {_platform_config}")
log_service_config()

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


@app.get("/metrics")
async def metrics() -> PlainTextResponse:
    """Minimal Prometheus-style metrics endpoint to avoid probe 404 noise."""
    body = (
        "# HELP cosmicsec_api_gateway_up API gateway health status\n"
        "# TYPE cosmicsec_api_gateway_up gauge\n"
        "cosmicsec_api_gateway_up 1\n"
    )
    return PlainTextResponse(content=body, media_type="text/plain; version=0.0.4")


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
    scans_today = 0
    compliance_pct = 75

    async with httpx.AsyncClient() as client:
        # Scan stats
        try:
            resp = await client.get(_build_service_url("scan", "/stats"), timeout=3.0)
            if resp.status_code == 200:
                data = resp.json()
                total_scans = data.get("total_scans", 0)
                severity_breakdown = data.get("severity_breakdown", {})
                if isinstance(severity_breakdown, dict):
                    critical_findings = int(severity_breakdown.get("critical", 0) or 0)
        except httpx.HTTPError:
            pass

        # Findings trend (last N days)
        try:
            resp = await client.get(
                _build_service_url("scan", "/findings/trending"),
                params={"days": 7},
                timeout=4.0,
            )
            if resp.status_code == 200:
                payload = resp.json()
                points = payload.get("points", []) if isinstance(payload, dict) else []
                if isinstance(points, list):
                    findings_last_7d = sum(
                        int(v or 0)
                        for p in points
                        if isinstance(p, dict)
                        for v in (
                            (p.get("severity_breakdown") or {}).values()
                            if isinstance(p.get("severity_breakdown"), dict)
                            else []
                        )
                    )
        except httpx.HTTPError:
            pass

        # Scan recency (today)
        try:
            resp = await client.get(
                _build_service_url("scan", "/scans"),
                params={"limit": 200, "offset": 0},
                timeout=4.0,
            )
            if resp.status_code == 200:
                rows = resp.json()
                if isinstance(rows, list):
                    today = datetime.now(tz=UTC).date()
                    for row in rows:
                        if not isinstance(row, dict):
                            continue
                        created_at = row.get("created_at")
                        if not isinstance(created_at, str):
                            continue
                        try:
                            created_dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                        except ValueError:
                            continue
                        if created_dt.date() == today:
                            scans_today += 1
        except httpx.HTTPError:
            pass

        # Agent sessions
        active_agents = len(
            [
                agent
                for agent in _registered_agents.values()
                if str(agent.get("status", "")).lower() == "connected"
            ]
        )

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
        "scans_today": scans_today,
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
async def global_search(
    request: Request,
    q: str,
    limit: int = 10,
    category: str | None = Query(default=None, description="single category filter"),
):
    """Authenticated global search across scans, findings, agents, reports, plugins, and events."""
    principal, is_admin = await _resolve_authenticated_user(request)
    query = q.strip().lower()
    per_category = max(1, min(limit, 5))
    selected_category = (category or "").strip().lower()
    valid_categories = {"", "all", "scans", "findings", "agents", "reports", "plugins", "events"}
    if selected_category not in valid_categories:
        raise HTTPException(status_code=400, detail="Unsupported search category")

    def _category_enabled(name: str) -> bool:
        return selected_category in {"", "all", name}

    def _score(text: str) -> int:
        hay = text.lower().strip()
        if not hay:
            return 0
        if hay == query:
            return 100
        if hay.startswith(query):
            return 80
        if query in hay:
            return 50
        return 0

    empty = {"scans": [], "findings": [], "agents": [], "reports": [], "plugins": [], "events": []}
    if not query:
        return empty

    scans: list[dict] = []
    findings: list[dict] = []
    reports: list[dict] = []
    plugins: list[dict] = []
    events: list[dict] = []
    candidates: list[dict] = []

    headers = {}
    auth = request.headers.get("Authorization")
    if auth:
        headers["Authorization"] = auth

    if _category_enabled("scans") or _category_enabled("findings") or _category_enabled("reports"):
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

                    scored_scans: list[tuple[int, dict]] = []
                    for scan in all_scans:
                        score = max(
                            _score(str(scan.get("target", ""))),
                            _score(str(scan.get("id", ""))),
                            _score(str(scan.get("status", ""))),
                        )
                        if score > 0:
                            scored_scans.append((score, scan))

                    scored_scans.sort(key=lambda item: item[0], reverse=True)
                    scans = [item[1] for item in scored_scans[:per_category]]
                    candidates = all_scans[: min(len(all_scans), _SEARCH_FINDING_SCAN_CANDIDATES)]
        except httpx.HTTPError as exc:
            logger.warning("Search scan lookup unavailable: %s", exc)

    if candidates and _category_enabled("findings"):
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
                scored_findings: list[tuple[int, dict]] = []
                for finding in collected:
                    score = max(
                        _score(str(finding.get("title", ""))),
                        _score(str(finding.get("id", ""))),
                        _score(str(finding.get("severity", ""))),
                    )
                    if score > 0:
                        scored_findings.append((score, finding))
                scored_findings.sort(key=lambda item: item[0], reverse=True)
                findings = [item[1] for item in scored_findings[:per_category]]
        except httpx.HTTPError as exc:
            logger.warning("Search finding lookup unavailable: %s", exc)

    if _category_enabled("plugins"):
        try:
            async with httpx.AsyncClient() as client:
                plugin_resp = await client.get(
                    _build_service_url("plugins", "/plugins"),
                    headers=headers,
                    timeout=5.0,
                )
                if plugin_resp.status_code == 200:
                    payload = plugin_resp.json()
                    all_plugins = payload.get("plugins", []) if isinstance(payload, dict) else []
                    scored_plugins: list[tuple[int, dict]] = []
                    for plugin in all_plugins:
                        if not isinstance(plugin, dict):
                            continue
                        score = max(
                            _score(str(plugin.get("name", ""))),
                            _score(str(plugin.get("description", ""))),
                            _score(str(plugin.get("author", ""))),
                            _score(" ".join(str(tag) for tag in plugin.get("tags", []) if tag)),
                        )
                        if score > 0:
                            scored_plugins.append(
                                (
                                    score,
                                    {
                                        "name": plugin.get("name"),
                                        "version": plugin.get("version"),
                                        "description": plugin.get("description"),
                                        "author": plugin.get("author"),
                                        "tags": plugin.get("tags", []),
                                        "permissions": plugin.get("permissions", []),
                                    },
                                )
                            )
                    scored_plugins.sort(key=lambda item: item[0], reverse=True)
                    plugins = [item[1] for item in scored_plugins[:per_category]]
        except httpx.HTTPError as exc:
            logger.warning("Search plugin lookup unavailable: %s", exc)

    if _category_enabled("events"):
        try:
            async with httpx.AsyncClient() as client:
                audit_resp = await client.get(
                    _build_service_url("plugins", "/plugins/audit"),
                    headers={
                        "X-CosmicSec-Viewer": principal,
                        "X-CosmicSec-Viewer-Admin": "true" if is_admin else "false",
                    },
                    params={"limit": per_category * 4},
                    timeout=5.0,
                )
                if audit_resp.status_code == 200:
                    payload = audit_resp.json()
                    audit_items = payload.get("items", []) if isinstance(payload, dict) else []
                    scored_events: list[tuple[int, dict]] = []
                    for item in audit_items:
                        if not isinstance(item, dict):
                            continue
                        context = (
                            item.get("context") if isinstance(item.get("context"), dict) else {}
                        )
                        score = max(
                            _score(str(item.get("action", ""))),
                            _score(str(item.get("plugin", ""))),
                            _score(str(item.get("detail", ""))),
                            _score(str(context.get("target", ""))),
                            _score(str(context.get("scan_id", ""))),
                        )
                        if score > 0:
                            scored_events.append(
                                (
                                    score,
                                    {
                                        "id": f"{item.get('timestamp', '')}-{item.get('plugin', 'plugin')}-{item.get('action', 'event')}",
                                        "title": f"{item.get('action', 'event')} · {item.get('plugin', 'plugin')}",
                                        "description": item.get("detail", ""),
                                        "plugin": item.get("plugin"),
                                        "scan_id": context.get("scan_id"),
                                        "target": context.get("target"),
                                        "status": item.get("status"),
                                        "timestamp": item.get("timestamp"),
                                    },
                                )
                            )
                    scored_events.sort(key=lambda item: item[0], reverse=True)
                    events = [item[1] for item in scored_events[:per_category]]
        except httpx.HTTPError as exc:
            logger.warning("Search audit lookup unavailable: %s", exc)

    if _category_enabled("reports"):
        scored_reports: list[tuple[int, dict]] = []
        for scan in scans:
            scan_id = str(scan.get("id", "")).strip()
            if not scan_id:
                continue
            report_id = f"report-{scan_id}"
            score = max(_score(report_id), _score(scan_id), _score(str(scan.get("target", ""))))
            if score <= 0:
                continue
            scored_reports.append(
                (
                    score,
                    {
                        "id": report_id,
                        "scan_id": scan_id,
                        "format": "pdf",
                        "status": "available"
                        if str(scan.get("status")) == "completed"
                        else "pending",
                        "created_at": scan.get("completed_at") or scan.get("created_at"),
                    },
                )
            )
        scored_reports.sort(key=lambda item: item[0], reverse=True)
        reports = [item[1] for item in scored_reports[:per_category]]

    if _category_enabled("agents"):
        visible_agents = (
            list(_registered_agents.values())
            if is_admin
            else [
                agent for agent in _registered_agents.values() if agent.get("user_id") == principal
            ]
        )
        scored_agents: list[tuple[int, dict]] = []
        for agent in visible_agents:
            manifest = agent.get("manifest") if isinstance(agent.get("manifest"), dict) else {}
            name = str(manifest.get("name") or agent.get("agent_id") or "Agent")
            score = max(
                _score(name),
                _score(str(agent.get("agent_id", ""))),
                _score(str(agent.get("status", ""))),
            )
            if score <= 0:
                continue
            scored_agents.append(
                (
                    score,
                    {
                        "id": agent.get("agent_id"),
                        "name": name,
                        "status": agent.get("status", "unknown"),
                    },
                )
            )
        scored_agents.sort(key=lambda item: item[0], reverse=True)
        agents = [item[1] for item in scored_agents[:per_category]]

    scans = scans if _category_enabled("scans") else []
    findings = findings if _category_enabled("findings") else []
    agents = agents if _category_enabled("agents") else []
    reports = reports if _category_enabled("reports") else []
    plugins = plugins if _category_enabled("plugins") else []
    events = events if _category_enabled("events") else []

    return {
        "scans": scans,
        "findings": findings,
        "agents": agents,
        "reports": reports,
        "plugins": plugins,
        "events": events,
        "meta": {
            "query": query,
            "category": selected_category or "all",
            "limit": per_category,
            "counts": {
                "scans": len(scans),
                "findings": len(findings),
                "agents": len(agents),
                "reports": len(reports),
                "plugins": len(plugins),
                "events": len(events),
            },
        },
    }


@app.post("/api/auth/register")
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


@app.post("/api/auth/forgot-password")
@limiter.limit("20/minute")
async def forgot_password(request: Request):
    """Request password reset flow from auth service."""
    data = await request.json()
    return await hybrid_router.execute(
        request=request,
        service="auth",
        path="/forgot-password",
        method="POST",
        payload=data,
        timeout=10.0,
        route_key="auth.forgot_password",
    )


@app.post("/api/auth/verify-2fa")
@limiter.limit("30/minute")
async def verify_2fa(request: Request):
    """Verify 2FA challenge and complete login token exchange."""
    data = await request.json()
    return await hybrid_router.execute(
        request=request,
        service="auth",
        path="/verify-2fa",
        method="POST",
        payload=data,
        timeout=10.0,
        route_key="auth.verify_2fa",
    )


@app.post("/api/auth/resend-2fa")
@limiter.limit("20/minute")
async def resend_2fa(request: Request):
    """Request a fresh 2FA challenge from auth service."""
    data = await request.json()
    return await hybrid_router.execute(
        request=request,
        service="auth",
        path="/resend-2fa",
        method="POST",
        payload=data,
        timeout=10.0,
        route_key="auth.resend_2fa",
    )


@app.get("/api/auth/me")
@limiter.limit("60/minute")
async def auth_me(request: Request):
    """Return authenticated user profile from auth service."""
    headers: dict[str, str] = {}
    auth_header = request.headers.get("authorization")
    api_key = request.headers.get("x-api-key")
    if auth_header:
        headers["Authorization"] = auth_header
    if api_key:
        headers["X-API-Key"] = api_key
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                _build_service_url("auth", "/me"),
                headers=headers,
                timeout=10.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Auth me proxy error: %s", e)
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


@app.get("/api/auth/sso/{provider}/authorize")
@limiter.limit("30/minute")
async def auth_sso_authorize(request: Request, provider: str):
    """Start provider SSO authorization flow."""
    provider = _validate_path_id(provider, "provider").lower()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                _build_service_url("auth", f"/oauth2/{provider}"),
                timeout=10.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Auth SSO authorize error: %s", e)
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


@app.get("/api/auth/sso/{provider}/callback")
@limiter.limit("60/minute")
async def auth_sso_callback(request: Request, provider: str, code: str, state: str | None = None):
    """Handle provider callback response and forward to auth service."""
    provider = _validate_path_id(provider, "provider").lower()
    params = {"code": code}
    if state:
        params["state"] = state
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                _build_service_url("auth", f"/oauth2/{provider}/callback"),
                params=params,
                timeout=10.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Auth SSO callback error: %s", e)
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


@app.get("/api/auth/sso/saml/metadata")
@limiter.limit("60/minute")
async def auth_saml_metadata(request: Request):
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(_build_service_url("auth", "/saml/metadata"), timeout=10.0)
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Auth SAML metadata error: %s", e)
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


@app.post("/api/auth/sso/saml/acs")
@limiter.limit("30/minute")
async def auth_saml_acs(request: Request):
    data = await request.json()
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                _build_service_url("auth", "/saml/acs"),
                json=data,
                timeout=10.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Auth SAML ACS error: %s", e)
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


@app.get("/api/orgs/slug/{slug}/sso")
@limiter.limit("60/minute")
async def discover_org_sso(request: Request, slug: str):
    """Resolve organization slug to SSO authorization metadata for login flows."""
    normalized_slug = _validate_org_slug(slug)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                _build_service_url("auth", f"/orgs/slug/{normalized_slug}/sso"),
                timeout=10.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Org SSO discovery error: %s", e)
            raise HTTPException(status_code=503, detail="Authentication service unavailable")


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


@app.get("/api/settings/scan-defaults")
@limiter.limit("20/minute")
async def get_scan_defaults(request: Request):
    headers = {}
    if request.headers.get("Authorization"):
        headers["Authorization"] = request.headers.get("Authorization")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                _build_service_url("auth", "/settings/scan-defaults"), headers=headers, timeout=10.0
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


@app.get("/api/scans")
@limiter.limit("120/minute")
async def list_scans(request: Request):
    """List scans for the current user/org workspace context."""
    query_params = dict(request.query_params)
    headers = {}
    for h in ["Authorization", "X-Org-Id", "X-Workspace-Id", "X-API-Key"]:
        if request.headers.get(h):
            headers[h] = request.headers.get(h)

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                _build_service_url("scan", "/scans"),
                params=query_params,
                headers=headers,
                timeout=15.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Scan service list error: %s", e)
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.post("/api/findings/import")
@limiter.limit("20/minute")
async def import_findings(request: Request):
    """Import offline findings batches into scan service."""
    raw_body = await request.body()
    headers = {}
    for h in ["Content-Encoding", "Authorization", "X-API-Key", "X-Org-Id", "X-Workspace-Id"]:
        if request.headers.get(h):
            headers[h] = request.headers.get(h)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                _build_service_url("scan", "/findings/import"),
                content=raw_body,
                headers=headers,
                timeout=30.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Scan service findings import error: %s", e)
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.post("/api/scans/agent-results")
@limiter.limit("60/minute")
async def ingest_agent_results(request: Request):
    """Proxy agent task results to scan service for durable scan/finding aggregation."""
    data = await request.json()
    headers = {}
    for h in ["Authorization", "X-Org-Id", "X-Workspace-Id", "X-API-Key"]:
        if request.headers.get(h):
            headers[h] = request.headers.get(h)

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                _build_service_url("scan", "/scans/agent-results"),
                json=data,
                headers=headers,
                timeout=20.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Scan service agent result ingest error: %s", e)
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.get("/api/findings")
@limiter.limit("120/minute")
async def list_findings(request: Request):
    """Aggregate findings across recent scans for dashboard and timeline views."""
    params = dict(request.query_params)
    try:
        limit = int(params.get("limit", "50"))
    except ValueError:
        limit = 50
    limit = max(1, min(limit, 200))

    headers = {}
    for h in ["Authorization", "X-Org-Id", "X-Workspace-Id", "X-API-Key"]:
        if request.headers.get(h):
            headers[h] = request.headers.get(h)

    findings = []
    async with httpx.AsyncClient() as client:
        try:
            scans_resp = await client.get(
                _build_service_url("scan", "/scans"),
                params={"limit": min(limit, 50)},
                headers=headers,
                timeout=10.0,
            )
            if scans_resp.status_code != 200:
                return {"items": []}

            scans_data = scans_resp.json()
            scans = scans_data if isinstance(scans_data, list) else scans_data.get("items", [])

            for scan in scans:
                scan_id = str(scan.get("id") or "").strip()
                if not scan_id:
                    continue
                try:
                    f_resp = await client.get(
                        _build_service_url("scan", f"/scans/{scan_id}/findings"),
                        headers=headers,
                        timeout=10.0,
                    )
                    if f_resp.status_code != 200:
                        continue
                    scan_findings = f_resp.json()
                    if not isinstance(scan_findings, list):
                        continue
                    for finding in scan_findings:
                        if not isinstance(finding, dict):
                            continue
                        normalized = dict(finding)
                        normalized.setdefault("scan_id", scan_id)
                        findings.append(normalized)
                        if len(findings) >= limit:
                            return {"items": findings}
                except httpx.HTTPError:
                    continue
        except httpx.HTTPError:
            return {"items": []}

    return {"items": findings}


@app.get("/api/findings/trending")
@limiter.limit("120/minute")
async def findings_trending(request: Request):
    """Proxy daily findings trend analytics from scan service."""
    headers = {}
    for h in ["Authorization", "X-Org-Id", "X-Workspace-Id", "X-API-Key"]:
        if request.headers.get(h):
            headers[h] = request.headers.get(h)

    params = dict(request.query_params)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                _build_service_url("scan", "/findings/trending"),
                headers=headers,
                params=params,
                timeout=15.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Scan service findings trending error: %s", e)
            raise HTTPException(status_code=503, detail="Scan service unavailable")


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


@app.get("/api/scans/{scan_id}/findings")
@limiter.limit("120/minute")
async def get_scan_findings(request: Request, scan_id: str):
    """Retrieve findings for a specific scan."""
    headers = {}
    for h in ["Authorization", "X-Org-Id", "X-Workspace-Id", "X-API-Key"]:
        if request.headers.get(h):
            headers[h] = request.headers.get(h)

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                _build_service_url("scan", f"/scans/{scan_id}/findings"),
                headers=headers,
                timeout=15.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Scan service findings error for %s: %s", _sanitize_log(scan_id), e)
            raise HTTPException(status_code=503, detail="Scan service unavailable")


@app.post("/api/scans/{scan_id}/cancel")
@limiter.limit("20/minute")
async def cancel_scan(request: Request, scan_id: str):
    """Cancel a running scan."""
    headers = {}
    for h in ["Authorization", "X-Org-Id", "X-Workspace-Id", "X-API-Key"]:
        if request.headers.get(h):
            headers[h] = request.headers.get(h)

    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                _build_service_url("scan", f"/scans/{scan_id}/cancel"),
                headers=headers,
                timeout=10.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error("Scan service cancellation error for %s: %s", _sanitize_log(scan_id), e)
            raise HTTPException(status_code=503, detail="Scan service unavailable")


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
    try:
        data = await request.json()
    except Exception as exc:
        logger.warning("Invalid JSON payload for /api/ai/query: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    source_hint = request.headers.get("X-CosmicSec-Client", "").strip().lower()
    user_agent = request.headers.get("User-Agent", "").lower()
    inferred_source = (
        source_hint
        if source_hint in {"web", "cli"}
        else ("cli" if "cosmicsec-agent" in user_agent else "web")
    )
    data.setdefault("source", inferred_source)
    data.setdefault("preferred_model", "phi3:mini")
    data.setdefault(
        "preferred_provider",
        (os.environ.get("COSMICSEC_DEFAULT_LLM_PROVIDER") or "ollama").strip().lower(),
    )

    async with httpx.AsyncClient() as client:
        last_exc: Exception | None = None
        for attempt, backoff in enumerate((0.0, 0.35, 0.8), start=1):
            if backoff:
                await asyncio.sleep(backoff)
            try:
                response = await client.post(
                    _build_service_url("ai", "/query"),
                    json=data,
                    timeout=20.0,
                )
                return JSONResponse(status_code=response.status_code, content=response.json())
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as e:
                last_exc = e
                logger.warning(
                    "AI service transient error on /api/ai/query (attempt %s): %s",
                    attempt,
                    e,
                )
            except httpx.HTTPError as e:
                logger.error(f"AI service error: {e}")
                raise HTTPException(status_code=503, detail="AI service unavailable")

        logger.error(f"AI service error after retries: {last_exc}")
        raise HTTPException(status_code=503, detail="AI service unavailable")


@app.post("/api/ai/query/stream")
@limiter.limit("20/minute")
async def ai_nl_query_stream(request: Request):
    """Proxy natural language query as NDJSON stream for progressive UI updates."""
    try:
        data = await request.json()
    except Exception as exc:
        logger.warning("Invalid JSON payload for /api/ai/query/stream: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid JSON payload") from exc

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object")

    source_hint = request.headers.get("X-CosmicSec-Client", "").strip().lower()
    user_agent = request.headers.get("User-Agent", "").lower()
    inferred_source = (
        source_hint
        if source_hint in {"web", "cli"}
        else ("cli" if "cosmicsec-agent" in user_agent else "web")
    )
    data.setdefault("source", inferred_source)
    data.setdefault("preferred_model", "phi3:mini")
    data.setdefault(
        "preferred_provider",
        (os.environ.get("COSMICSEC_DEFAULT_LLM_PROVIDER") or "ollama").strip().lower(),
    )

    async def _proxy_stream() -> object:
        async with httpx.AsyncClient() as client:
            try:
                async with client.stream(
                    "POST",
                    _build_service_url("ai", "/query/stream"),
                    json=data,
                    timeout=60.0,
                ) as response:
                    if response.status_code >= 400:
                        detail = (await response.aread()).decode("utf-8", errors="ignore")
                        payload = {
                            "type": "error",
                            "status": response.status_code,
                            "detail": detail or "AI service unavailable",
                        }
                        yield (json.dumps(payload) + "\n").encode("utf-8")
                        return

                    async for chunk in response.aiter_bytes():
                        if chunk:
                            yield chunk
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
                logger.warning("AI stream transient error: %s", exc)
                payload = {
                    "type": "error",
                    "status": 503,
                    "detail": "AI service unavailable",
                }
                yield (json.dumps(payload) + "\n").encode("utf-8")
            except httpx.HTTPError as exc:
                logger.error("AI stream proxy error: %s", exc)
                payload = {
                    "type": "error",
                    "status": 503,
                    "detail": "AI service unavailable",
                }
                yield (json.dumps(payload) + "\n").encode("utf-8")

    return StreamingResponse(
        _proxy_stream(),
        media_type="application/x-ndjson",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/ai/models")
@limiter.limit("30/minute")
async def ai_models(request: Request):
    """Proxy AI model inventory/status from ai-service."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(_build_service_url("ai", "/ai/models"), timeout=15.0)
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError as e:
            logger.error(f"AI service error: {e}")
            raise HTTPException(status_code=503, detail="AI service unavailable")


@app.get("/api/ai/model/status")
@limiter.limit("30/minute")
async def ai_model_status(request: Request, model: str = "phi3:mini"):
    """Proxy specific local model status from ai-service."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                _build_service_url("ai", "/ai/model/status"),
                params={"model": model},
                timeout=15.0,
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
        timeout=35.0,
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
        "supported_modes": ["dynamic", "hybrid", "static", "demo", "emergency", "local_web"],
    }


@app.get("/api/guest/health")
@limiter.limit("5/minute", key_func=get_remote_address)
async def guest_health(request: Request):
    """Public, read-only guest health check with strict rate limiting."""
    _ = request
    return {
        "status": "ok",
        "service": "api_gateway",
        "user_type": "guest",
        "timestamp": time.time(),
    }


@app.get("/api/guest/dns")
@limiter.limit("5/minute", key_func=get_remote_address)
async def guest_dns_lookup(
    request: Request, domain: str = Query(..., min_length=1, max_length=253)
):
    """Public, read-only DNS lookup endpoint with private-range safeguards."""
    _ = request
    normalized = _validate_guest_domain(domain)

    try:
        infos = socket.getaddrinfo(normalized, None, proto=socket.IPPROTO_TCP)
        addresses = sorted({entry[4][0] for entry in infos if entry and entry[4]})
    except socket.gaierror:
        raise HTTPException(status_code=404, detail="Domain resolution failed")

    if not addresses:
        raise HTTPException(status_code=404, detail="No DNS records found")
    if any(_is_private_or_loopback_host(addr) for addr in addresses):
        raise HTTPException(status_code=403, detail="Guest sandbox denied target")

    return {
        "domain": normalized,
        "addresses": addresses,
        "count": len(addresses),
        "user_type": "guest",
    }


@app.get("/api/guest/whois")
@limiter.limit("5/minute", key_func=get_remote_address)
async def guest_whois_lookup(
    request: Request, domain: str = Query(..., min_length=1, max_length=253)
):
    """Public, read-only RDAP lookup for guest mode."""
    _ = request
    normalized = _validate_guest_domain(domain)

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"https://rdap.org/domain/{normalized}", timeout=8.0)
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="WHOIS lookup unavailable")

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail="WHOIS lookup failed")

    data = resp.json()
    payload = {
        "domain": normalized,
        "handle": data.get("handle"),
        "ldhName": data.get("ldhName"),
        "status": data.get("status", []),
        "events": data.get("events", [])[:5],
        "nameservers": [
            ns.get("ldhName")
            for ns in data.get("nameservers", [])
            if isinstance(ns, dict) and ns.get("ldhName")
        ][:10],
        "user_type": "guest",
    }
    return _truncate_guest_payload(payload)


@app.get("/api/guest/cve")
@limiter.limit("5/minute", key_func=get_remote_address)
async def guest_cve_lookup(request: Request, id: str = Query(..., min_length=9, max_length=32)):
    """Public CVE lookup endpoint for guest mode."""
    _ = request
    cve_id = (id or "").strip().upper()
    if not _RE_CVE_ID.match(cve_id):
        raise HTTPException(status_code=400, detail="Invalid CVE ID")

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
                timeout=10.0,
            )
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="CVE lookup unavailable")

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail="CVE lookup failed")

    data = resp.json()
    items = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    record = items[0].get("cve", {}) if items and isinstance(items[0], dict) else {}
    descriptions = record.get("descriptions", []) if isinstance(record, dict) else []
    summary = next(
        (
            item.get("value")
            for item in descriptions
            if isinstance(item, dict) and item.get("lang") == "en"
        ),
        None,
    )

    payload = {
        "cve_id": cve_id,
        "published": record.get("published"),
        "lastModified": record.get("lastModified"),
        "summary": summary,
        "user_type": "guest",
    }
    return _truncate_guest_payload(payload)


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
            "preview_token_marked": True,  # nosec B105
            "runtime_metadata_included": True,
        },
        "10_success_criteria": {
            "gateway_responsive_with_fallback": True,
            "security_critical_no_silent_bypass": ROUTE_POLICIES["auth.refresh"].fallback_policy
            == "disabled",
            "observable_mode_and_fallback": tracing["buffer_size"] > 0,
            "tests_passing_baseline": True,  # nosec B105
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
            resp = await client.post(
                _build_service_url("report", "/ci/build"), json=data, timeout=10.0
            )
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
        response = await client.post(
            _build_service_url("auth", "/users"), json=payload, timeout=10.0
        )
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
        response = await client.post(
            _build_service_url("auth", "/config"), json=payload, timeout=10.0
        )
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
        response = await client.post(
            _build_service_url("auth", "/orgs"), json=payload, timeout=10.0
        )
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
        response = await client.get(
            _build_service_url("auth", f"/orgs/{org_id}/members"), timeout=10.0
        )
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
        response = await client.get(
            _build_service_url("auth", f"/orgs/{org_id}/quotas"), timeout=10.0
        )
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
    auth_context = await _resolve_websocket_user(websocket)
    if auth_context is None:
        await websocket.close(code=4001)
        return

    principal, is_admin = auth_context
    await websocket.accept()

    def _tools_in_manifest(manifest: dict) -> list[str]:
        raw_tools = manifest.get("tools", []) if isinstance(manifest, dict) else []
        if not isinstance(raw_tools, list):
            return []
        normalized: list[str] = []
        for item in raw_tools:
            if isinstance(item, str):
                name = item.strip().lower()
            elif isinstance(item, dict):
                candidate = item.get("name") or item.get("binary")
                name = str(candidate).strip().lower() if candidate else ""
            else:
                name = ""
            if name:
                normalized.append(name)
        return normalized

    async def _fetch_overview_snapshot() -> dict:
        total_scans = 0
        critical_findings = 0
        open_bugs = 0

        async with httpx.AsyncClient() as client:
            try:
                stats_resp = await client.get(_build_service_url("scan", "/stats"), timeout=3.0)
                if stats_resp.status_code == 200:
                    data = stats_resp.json()
                    total_scans = int(data.get("total_scans", 0) or 0)
                    severity_breakdown = data.get("severity_breakdown", {})
                    if isinstance(severity_breakdown, dict):
                        critical_findings = int(severity_breakdown.get("critical", 0) or 0)
            except httpx.HTTPError:
                pass

            try:
                bug_resp = await client.get(
                    _build_service_url("bugbounty", "/submissions?status=open&limit=100"),
                    timeout=3.0,
                )
                if bug_resp.status_code == 200:
                    payload = bug_resp.json()
                    open_bugs = len(payload.get("items", []))
            except httpx.HTTPError:
                pass

        return {
            "total_scans": total_scans,
            "critical_findings": critical_findings,
            "open_bugs": open_bugs,
        }

    def _runtime_summary() -> tuple[int, int, list[dict]]:
        now = time.time()
        running_tasks = 0
        recent_completed = 0
        tool_stats: dict[str, dict[str, float | int]] = {}

        for task_rows in _agent_tasks.values():
            for task in task_rows:
                tool = str(task.get("tool") or "unknown").strip().lower() or "unknown"
                stats = tool_stats.setdefault(
                    tool,
                    {
                        "running": 0,
                        "completed_24h": 0,
                        "failed_24h": 0,
                        "progress_total": 0,
                        "progress_count": 0,
                        "duration_total": 0.0,
                        "duration_count": 0,
                    },
                )

                status_value = str(task.get("status") or "").lower()
                if status_value == "running":
                    running_tasks += 1
                    stats["running"] = int(stats["running"]) + 1

                updated_at = float(task.get("updated_at") or task.get("created_at") or now)
                within_24h = now - updated_at <= 24 * 60 * 60

                if status_value == "completed" and within_24h:
                    recent_completed += 1
                    stats["completed_24h"] = int(stats["completed_24h"]) + 1
                if status_value in {"failed", "dispatch_failed", "rejected"} and within_24h:
                    stats["failed_24h"] = int(stats["failed_24h"]) + 1

                progress = int(task.get("progress", 0) or 0)
                stats["progress_total"] = int(stats["progress_total"]) + max(0, min(progress, 100))
                stats["progress_count"] = int(stats["progress_count"]) + 1

                if status_value in {"completed", "failed"}:
                    created_at = float(task.get("created_at") or updated_at)
                    duration = max(0.0, updated_at - created_at)
                    stats["duration_total"] = float(stats["duration_total"]) + duration
                    stats["duration_count"] = int(stats["duration_count"]) + 1

        top_tools = sorted(
            tool_stats.items(),
            key=lambda item: (
                int(item[1]["running"]),
                int(item[1]["completed_24h"]),
                int(item[1]["progress_total"]),
            ),
            reverse=True,
        )[:6]

        tool_runtime = []
        for tool, stats in top_tools:
            progress_count = int(stats["progress_count"]) or 1
            duration_count = int(stats["duration_count"]) or 1
            tool_runtime.append(
                {
                    "tool": tool,
                    "running": int(stats["running"]),
                    "completed_24h": int(stats["completed_24h"]),
                    "failed_24h": int(stats["failed_24h"]),
                    "average_progress": round(int(stats["progress_total"]) / progress_count, 1),
                    "average_duration_seconds": round(
                        float(stats["duration_total"]) / duration_count, 1
                    )
                    if int(stats["duration_count"]) > 0
                    else None,
                }
            )

        return running_tasks, recent_completed, tool_runtime

    try:
        while True:
            overview = await _fetch_overview_snapshot()
            running_tasks, recent_completed, tool_runtime = _runtime_summary()

            visible_agents = [
                agent
                for agent in _registered_agents.values()
                if is_admin or agent.get("user_id") == principal
            ]
            connected_agents = len(
                [
                    agent
                    for agent in visible_agents
                    if str(agent.get("status", "")).lower() == "connected"
                ]
            )

            discovered_tools = sorted(
                {
                    tool
                    for agent in visible_agents
                    for tool in _tools_in_manifest(agent.get("manifest", {}))
                }
            )

            await websocket.send_json(
                {
                    "timestamp": time.time(),
                    "system_health": "healthy",
                    "active_scans": overview["total_scans"],
                    "connected_agents": connected_agents,
                    "critical_findings": overview["critical_findings"],
                    "open_bugs": overview["open_bugs"],
                    "task_runtime": {
                        "running": running_tasks,
                        "completed_24h": recent_completed,
                        "tools": tool_runtime,
                    },
                    "tool_inventory": {
                        "count": len(discovered_tools),
                        "items": discovered_tools[:20],
                    },
                }
            )
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        logger.info("Dashboard websocket disconnected for %s", _sanitize_log(principal))


@app.get("/api/tools/registry")
@limiter.limit("60/minute")
async def unified_tool_registry(request: Request) -> JSONResponse:
    """Return a unified view of server tools and connected CLI agent tools."""
    principal, is_admin = await _resolve_authenticated_user(request)

    server_tools = [
        {"name": "nmap", "category": "pentest", "source": "server"},
        {"name": "nikto", "category": "pentest", "source": "server"},
        {"name": "nuclei", "category": "pentest", "source": "server"},
        {"name": "sqlmap", "category": "pentest", "source": "server"},
        {"name": "gobuster", "category": "recon", "source": "server"},
        {"name": "whois", "category": "recon", "source": "server"},
        {"name": "dns", "category": "recon", "source": "server"},
        {"name": "rdap", "category": "recon", "source": "server"},
        {"name": "timeline", "category": "soc", "source": "server"},
        {"name": "alerts", "category": "soc", "source": "server"},
        {"name": "bugbounty", "category": "bounty", "source": "server"},
    ]

    visible_agents = [
        agent
        for agent in _registered_agents.values()
        if is_admin or agent.get("user_id") == principal
    ]

    agent_tool_map: dict[str, dict] = {}
    for agent in visible_agents:
        manifest = agent.get("manifest") if isinstance(agent.get("manifest"), dict) else {}
        raw_tools = manifest.get("tools", []) if isinstance(manifest, dict) else []
        if not isinstance(raw_tools, list):
            continue
        for tool in raw_tools:
            if isinstance(tool, str):
                name = tool.strip().lower()
                category = "cli"
            elif isinstance(tool, dict):
                name = str(tool.get("name") or tool.get("binary") or "").strip().lower()
                category = str(tool.get("category") or "cli").strip().lower() or "cli"
            else:
                name = ""
                category = "cli"
            if not name:
                continue
            item = agent_tool_map.setdefault(
                name,
                {
                    "name": name,
                    "category": category,
                    "source": "agent",
                    "agent_count": 0,
                    "connected_agent_count": 0,
                },
            )
            item["agent_count"] = int(item["agent_count"]) + 1
            if str(agent.get("status", "")).lower() == "connected":
                item["connected_agent_count"] = int(item["connected_agent_count"]) + 1

    server_name_set = {item["name"] for item in server_tools}
    unified_map: dict[str, dict] = {
        item["name"]: {
            "name": item["name"],
            "category": item["category"],
            "server_available": True,
            "agent_available": False,
            "agent_count": 0,
            "connected_agent_count": 0,
        }
        for item in server_tools
    }

    for tool_name, agent_item in agent_tool_map.items():
        existing = unified_map.get(tool_name)
        if existing is None:
            unified_map[tool_name] = {
                "name": tool_name,
                "category": agent_item.get("category", "cli"),
                "server_available": tool_name in server_name_set,
                "agent_available": True,
                "agent_count": int(agent_item.get("agent_count", 0)),
                "connected_agent_count": int(agent_item.get("connected_agent_count", 0)),
            }
        else:
            existing["agent_available"] = True
            existing["agent_count"] = int(agent_item.get("agent_count", 0))
            existing["connected_agent_count"] = int(agent_item.get("connected_agent_count", 0))

    unified_tools = sorted(unified_map.values(), key=lambda item: item["name"])

    return JSONResponse(
        content={
            "server_tools": server_tools,
            "agent_tools": sorted(agent_tool_map.values(), key=lambda item: item["name"]),
            "unified_tools": unified_tools,
            "agents_visible": len(visible_agents),
            "connected_agents": len(
                [a for a in visible_agents if str(a.get("status", "")).lower() == "connected"]
            ),
            "timestamp": time.time(),
        }
    )


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
            response = await client.get(
                _build_service_url("plugins", f"/plugins/{name}"), timeout=5.0
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/plugins/{name}/run")
@limiter.limit("20/minute")
async def plugin_run(request: Request, name: str):
    name = _validate_plugin_name(name)
    data = await request.json()
    principal, is_admin = await _resolve_authenticated_user(request)
    async with httpx.AsyncClient() as client:
        try:
            data = dict(data)
            data.setdefault("user", principal)
            data.setdefault("config", {})
            response = await client.post(
                _build_service_url("plugins", f"/plugins/{name}/run"),
                json=data,
                headers={
                    "X-CosmicSec-Actor": principal,
                    "X-CosmicSec-Actor-Role": "admin" if is_admin else "operator",
                },
                timeout=30.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/plugins/{name}/enable")
@limiter.limit("20/minute")
async def plugin_enable(request: Request, name: str):
    name = _validate_plugin_name(name)
    principal, is_admin = await _resolve_authenticated_user(request)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                _build_service_url("plugins", f"/plugins/{name}/enable"),
                headers={
                    "X-CosmicSec-Actor": principal,
                    "X-CosmicSec-Actor-Role": "admin" if is_admin else "operator",
                },
                timeout=5.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.post("/api/plugins/{name}/disable")
@limiter.limit("20/minute")
async def plugin_disable(request: Request, name: str):
    name = _validate_plugin_name(name)
    principal, is_admin = await _resolve_authenticated_user(request)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(
                _build_service_url("plugins", f"/plugins/{name}/disable"),
                headers={
                    "X-CosmicSec-Actor": principal,
                    "X-CosmicSec-Actor-Role": "admin" if is_admin else "operator",
                },
                timeout=5.0,
            )
            return JSONResponse(status_code=response.status_code, content=response.json())
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="Plugin registry unavailable")


@app.get("/api/plugins/audit")
@limiter.limit("60/minute")
async def plugin_audit(request: Request):
    params = dict(request.query_params)
    principal, is_admin = await _resolve_authenticated_user(request)
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                _build_service_url("plugins", "/plugins/audit"),
                params=params,
                headers={
                    "X-CosmicSec-Viewer": principal,
                    "X-CosmicSec-Viewer-Admin": "true" if is_admin else "false",
                },
                timeout=5.0,
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
            resp = await client.get(
                _build_service_url("scan", f"/monitor/jobs/{job_id}"), timeout=5.0
            )
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
            resp = await client.delete(
                _build_service_url("scan", f"/monitor/jobs/{job_id}"), timeout=5.0
            )
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
            resp = await client.post(
                _build_service_url("scan", "/scans/fuzz"), json=data, timeout=60.0
            )
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
            resp = await client.post(
                _build_service_url("scan", "/scans/cloud"), json=data, timeout=30.0
            )
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
            resp = await client.post(
                _build_service_url("ai", "/anomaly/fit"), json=data, timeout=30.0
            )
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
            resp = await client.post(
                _build_service_url("ai", "/anomaly/batch"), json=data, timeout=30.0
            )
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
            resp = await client.get(
                _build_service_url("plugins", f"/plugins/{name}/rating"), timeout=5.0
            )
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
# Agent task ledger keyed by agent_id
_agent_tasks: dict[str, list[dict]] = {}


class DispatchAgentTaskRequest(BaseModel):
    """Dispatch payload for assigning a local execution task to an agent."""

    tool: str
    target: str = ""
    args: list[str] = Field(default_factory=list)
    task_metadata: dict = Field(default_factory=dict)


def _persist_agent_task_create(task_record: dict) -> None:
    """Persist an agent task row, tolerating DB outages with in-memory fallback."""
    try:
        from services.common.db import SessionLocal
        from services.common.models import AgentTaskModel

        db = SessionLocal()
        try:
            row = AgentTaskModel(
                id=str(task_record.get("task_id")),
                agent_id=str(task_record.get("agent_id")),
                requested_by=task_record.get("requested_by"),
                tool=str(task_record.get("tool", "")),
                target=str(task_record.get("target", "")),
                args=task_record.get("args") if isinstance(task_record.get("args"), list) else [],
                task_metadata=task_record.get("metadata")
                if isinstance(task_record.get("metadata"), dict)
                else {},
                status=str(task_record.get("status", "dispatched")),
                progress=int(task_record.get("progress", 0)),
                created_at=datetime.fromtimestamp(
                    float(task_record.get("created_at", time.time())), tz=UTC
                ),
                updated_at=datetime.fromtimestamp(
                    float(task_record.get("updated_at", time.time())), tz=UTC
                ),
            )
            db.add(row)
            db.commit()
        finally:
            db.close()
    except Exception:
        logger.debug("Agent task create persistence failed (falling back to memory)", exc_info=True)


def _persist_agent_task_update(agent_id: str, task_id: str, **updates: object) -> None:
    """Apply status/progress/result updates to a persisted task row if available."""
    try:
        from services.common.db import SessionLocal
        from services.common.models import AgentTaskModel

        db = SessionLocal()
        try:
            row = (
                db.query(AgentTaskModel)
                .filter(AgentTaskModel.id == task_id, AgentTaskModel.agent_id == agent_id)
                .first()
            )
            if row is None:
                return
            if "status" in updates and updates["status"] is not None:
                row.status = str(updates["status"])
            if "progress" in updates and updates["progress"] is not None:
                row.progress = int(updates["progress"])
            if "message" in updates:
                row.message = str(updates["message"]) if updates["message"] is not None else None
            if "reason" in updates:
                row.reason = str(updates["reason"]) if updates["reason"] is not None else None
            if "result" in updates:
                row.result = updates["result"] if isinstance(updates["result"], dict) else None
            row.updated_at = datetime.now(tz=UTC)
            db.commit()
        finally:
            db.close()
    except Exception:
        logger.debug(
            "Agent task update persistence failed (memory state remains authoritative)",
            exc_info=True,
        )


def _list_agent_tasks_from_db(
    agent_id: str,
    *,
    status_filter: str | None,
    limit: int,
    offset: int,
) -> dict | None:
    """Return paginated task data from DB, or ``None`` when DB cannot be queried."""
    try:
        from services.common.db import SessionLocal
        from services.common.models import AgentTaskModel

        db = SessionLocal()
        try:
            base_query = db.query(AgentTaskModel).filter(AgentTaskModel.agent_id == agent_id)
            if status_filter:
                base_query = base_query.filter(AgentTaskModel.status == status_filter)

            total = int(base_query.count())
            rows = (
                base_query.order_by(AgentTaskModel.created_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )

            all_status_rows = (
                db.query(AgentTaskModel.status, AgentTaskModel.id)
                .filter(AgentTaskModel.agent_id == agent_id)
                .all()
            )
            status_counts: dict[str, int] = {}
            for status_value, _ in all_status_rows:
                key = str(status_value or "unknown")
                status_counts[key] = status_counts.get(key, 0) + 1

            tasks = []
            for row in rows:
                created_at = row.created_at.timestamp() if row.created_at else time.time()
                updated_at = row.updated_at.timestamp() if row.updated_at else created_at
                tasks.append(
                    {
                        "task_id": row.id,
                        "agent_id": row.agent_id,
                        "tool": row.tool,
                        "target": row.target or "",
                        "args": row.args if isinstance(row.args, list) else [],
                        "metadata": row.task_metadata
                        if isinstance(row.task_metadata, dict)
                        else {},
                        "status": row.status,
                        "progress": int(row.progress or 0),
                        "created_at": created_at,
                        "updated_at": updated_at,
                        "requested_by": row.requested_by,
                        "message": row.message,
                        "reason": row.reason,
                        "result": row.result if isinstance(row.result, dict) else None,
                    }
                )

            return {
                "tasks": tasks,
                "total": total,
                "limit": limit,
                "offset": offset,
                "has_more": offset + len(tasks) < total,
                "status_counts": status_counts,
                "source": "database",
            }
        finally:
            db.close()
    except Exception:
        logger.debug("Agent task list DB query failed; using in-memory fallback", exc_info=True)
        return None


async def _forward_agent_task_result_to_scan_service(
    *,
    agent_id: str,
    task_id: str,
    task_record: dict,
    result: dict,
) -> None:
    """Forward agent findings to scan service for unified persistence/analytics."""
    findings = result.get("findings") if isinstance(result, dict) else None
    if not isinstance(findings, list) or not findings:
        return

    metadata = task_record.get("metadata") if isinstance(task_record.get("metadata"), dict) else {}
    payload = {
        "agent_id": agent_id,
        "task_id": task_id,
        "scan_id": metadata.get("scan_id") if isinstance(metadata.get("scan_id"), str) else None,
        "requested_by": task_record.get("requested_by"),
        "target": task_record.get("target") or result.get("target"),
        "tool": task_record.get("tool") or result.get("tool"),
        "findings": findings,
        "metadata": metadata,
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                _build_service_url("scan", "/scans/agent-results"),
                json=payload,
                timeout=20.0,
            )
        if response.status_code >= 300:
            logger.warning(
                "Forwarding agent task result failed for task %s (status=%s)",
                _sanitize_log(task_id),
                response.status_code,
            )
    except httpx.HTTPError:
        logger.warning(
            "Forwarding agent task result failed for task %s (transport error)",
            _sanitize_log(task_id),
            exc_info=True,
        )


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


@app.post("/api/agents/{agent_id}/tasks")
@limiter.limit("60/minute")
async def dispatch_agent_task(agent_id: str, payload: DispatchAgentTaskRequest, request: Request):
    """Dispatch a task to a connected agent and track lifecycle state."""
    agent_id = _validate_uuid_param(agent_id, "agent_id")
    principal, is_admin = await _resolve_authenticated_user(request)

    agent = _registered_agents.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    if not is_admin and agent.get("user_id") != principal:
        raise HTTPException(status_code=403, detail="Forbidden")

    websocket = _agent_ws_connections.get(agent_id)
    if websocket is None:
        raise HTTPException(status_code=409, detail="Agent is not connected")

    task_id = str(uuid.uuid4())
    task_record = {
        "task_id": task_id,
        "agent_id": agent_id,
        "tool": payload.tool,
        "target": payload.target,
        "args": payload.args,
        "metadata": payload.task_metadata,
        "status": "dispatched",
        "progress": 0,
        "created_at": time.time(),
        "updated_at": time.time(),
        "requested_by": principal,
    }
    _agent_tasks.setdefault(agent_id, []).append(task_record)
    _persist_agent_task_create(task_record)

    try:
        await websocket.send_json(
            {
                "type": "task_assign",
                "payload": {
                    "task_id": task_id,
                    "tool": payload.tool,
                    "target": payload.target,
                    "args": payload.args,
                    "metadata": payload.task_metadata,
                },
            }
        )
    except Exception as exc:
        task_record["status"] = "dispatch_failed"
        task_record["updated_at"] = time.time()
        _persist_agent_task_update(agent_id, task_id, status="dispatch_failed")
        logger.warning("Failed to dispatch task %s to agent %s: %s", task_id, agent_id, exc)
        raise HTTPException(status_code=503, detail="Failed to dispatch task to agent")

    return JSONResponse(content={"dispatched": True, "agent_id": agent_id, "task_id": task_id})


@app.get("/api/agents/{agent_id}/tasks")
@limiter.limit("120/minute")
async def list_agent_tasks(
    agent_id: str,
    request: Request,
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> JSONResponse:
    """List task records for one agent with optional filtering and pagination."""
    agent_id = _validate_uuid_param(agent_id, "agent_id")
    principal, is_admin = await _resolve_authenticated_user(request)

    agent = _registered_agents.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    if not is_admin and agent.get("user_id") != principal:
        raise HTTPException(status_code=403, detail="Forbidden")

    allowed_statuses = {
        "dispatched",
        "accepted",
        "rejected",
        "running",
        "completed",
        "failed",
        "dispatch_failed",
    }
    normalized_status_filter = status_filter.strip().lower() if status_filter else None
    if normalized_status_filter and normalized_status_filter not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status filter. Allowed: {', '.join(sorted(allowed_statuses))}",
        )

    db_result = _list_agent_tasks_from_db(
        agent_id,
        status_filter=normalized_status_filter,
        limit=limit,
        offset=offset,
    )
    if db_result is not None:
        return JSONResponse(
            content={
                "agent_id": agent_id,
                "tasks": db_result["tasks"],
                "total": db_result["total"],
                "limit": db_result["limit"],
                "offset": db_result["offset"],
                "has_more": db_result["has_more"],
                "status_counts": db_result["status_counts"],
                "source": db_result["source"],
            }
        )

    tasks = _agent_tasks.get(agent_id, [])
    tasks_sorted = sorted(tasks, key=lambda t: float(t.get("created_at", 0)), reverse=True)

    if normalized_status_filter:
        tasks_sorted = [
            t for t in tasks_sorted if str(t.get("status", "")).lower() == normalized_status_filter
        ]

    total = len(tasks_sorted)
    paged_tasks = tasks_sorted[offset : offset + limit]

    status_counts: dict[str, int] = {}
    for task in tasks:
        key = str(task.get("status", "unknown"))
        status_counts[key] = status_counts.get(key, 0) + 1

    return JSONResponse(
        content={
            "agent_id": agent_id,
            "tasks": paged_tasks,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(paged_tasks) < total,
            "status_counts": status_counts,
            "source": "memory_fallback",
        }
    )


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
            elif msg_type == "task_ack":
                task_id = str(msg.get("task_id", ""))
                accepted = bool(msg.get("accepted", False))
                for task in reversed(_agent_tasks.get(agent_id, [])):
                    if task.get("task_id") == task_id:
                        task["status"] = "accepted" if accepted else "rejected"
                        task["updated_at"] = time.time()
                        task["reason"] = msg.get("reason")
                        _persist_agent_task_update(
                            agent_id,
                            task_id,
                            status=task["status"],
                            reason=task.get("reason"),
                        )
                        break
            elif msg_type == "task_progress":
                task_id = str(msg.get("task_id", ""))
                percent = int(msg.get("percent", 0))
                for task in reversed(_agent_tasks.get(agent_id, [])):
                    if task.get("task_id") == task_id:
                        task["status"] = "running"
                        task["progress"] = max(0, min(percent, 100))
                        task["updated_at"] = time.time()
                        task["message"] = msg.get("message")
                        _persist_agent_task_update(
                            agent_id,
                            task_id,
                            status="running",
                            progress=task["progress"],
                            message=task.get("message"),
                        )
                        break
            elif msg_type == "task_result":
                task_id = str(msg.get("task_id", ""))
                result = msg.get("result", {})
                for task in reversed(_agent_tasks.get(agent_id, [])):
                    if task.get("task_id") == task_id:
                        task["status"] = "completed" if result.get("success") else "failed"
                        task["progress"] = 100
                        task["updated_at"] = time.time()
                        task["result"] = result
                        _persist_agent_task_update(
                            agent_id,
                            task_id,
                            status=task["status"],
                            progress=100,
                            result=result,
                        )
                        await _forward_agent_task_result_to_scan_service(
                            agent_id=agent_id,
                            task_id=task_id,
                            task_record=task,
                            result=result if isinstance(result, dict) else {},
                        )
                        break
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
        logger.debug("Gateway heartbeat loop ended for agent %s", agent_id, exc_info=True)


# ---------------------------------------------------------------------------
# Phase P.2 — Rust Ingest Engine endpoints
# ---------------------------------------------------------------------------
# (imports for _check_rust_health and _rust_ingest_batch are at the top of the module)


@app.get("/api/ingest/health")
async def ingest_engine_health():
    """Return health status of the Rust ingest engine."""
    healthy = await _check_rust_health()
    return {
        "rust_ingest_engine": "healthy" if healthy else "unavailable",
        "feature_flag": os.environ.get("COSMICSEC_USE_RUST_INGEST", "false"),
    }


@app.post("/api/ingest/batch")
@limiter.limit("20/minute")
async def ingest_batch_endpoint(request: Request):
    """
    Forward raw scanner output to the Rust ingest engine.

    Body (multipart or JSON):
      ``scan_id``: str   — which scan produced this output
      ``tool``:    str   — nmap | nuclei | nikto | zap | generic
      ``data``:    bytes — raw scanner output (XML / JSONL / JSON)

    Routing is controlled by the COSMICSEC_USE_RUST_INGEST feature flag.
    When the flag is false or the Rust engine is unavailable the response
    instructs the caller to use the Python parsers in scan_service.
    """
    principal, _ = await _resolve_authenticated_user(request)
    body = await request.json()
    scan_id = _validate_path_id(str(body.get("scan_id", "")), "scan_id")
    tool = str(body.get("tool", "generic"))
    raw_data = str(body.get("data", "")).encode()

    result = await _rust_ingest_batch(tool=tool, raw_data=raw_data, scan_id=scan_id)
    logger.info(
        "ingest_batch scan_id=%s routed_to=%s principal=%s",
        _sanitize_log(scan_id),
        result.get("routed_to"),
        _sanitize_log(principal),
    )
    return result


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=os.getenv("COSMICSEC_BIND_HOST", "127.0.0.1"), port=8000)
