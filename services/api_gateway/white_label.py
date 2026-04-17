"""
Phase R.5 — White-Label Middleware & Branding API.

Provides:
  - `WhiteLabelMiddleware`: injects org branding into every response as
    custom headers (X-Org-Name, X-Primary-Color, X-Logo-URL) readable
    by the frontend to apply CSS variables and show the org logo.
  - In-memory branding store (DB-backed in production via org_service).
  - `/api/branding/{org_slug}` endpoint returning CSS variable payload
    for frontend theming without round-tripping to the org service.

Usage in API gateway::

    from services.api_gateway.white_label import WhiteLabelMiddleware, mount_branding_routes
    app.add_middleware(WhiteLabelMiddleware)
    mount_branding_routes(app)
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import quote

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from services.common.security_utils import (
    normalize_org_slug,
    sanitize_for_log,
    validate_outbound_url,
)

logger = logging.getLogger(__name__)

ORG_SERVICE_URL = os.getenv("ORG_SERVICE_URL", "http://org-service:8006")
_SAFE_ORG_SERVICE_URL = validate_outbound_url(ORG_SERVICE_URL, allow_private_hosts=True)

# ---------------------------------------------------------------------------
# In-memory branding cache (populated from org service)
# ---------------------------------------------------------------------------

_branding_cache: dict[str, dict[str, Any]] = {
    "default": {
        "name": "CosmicSec",
        "slug": "cosmicsec",
        "primary_color": "#6366f1",  # Indigo
        "accent_color": "#06b6d4",  # Cyan
        "background_color": "#0f172a",
        "logo_url": "/static/logo.svg",
        "favicon_url": "/static/favicon.ico",
        "custom_css": "",
    }
}


def get_branding(org_slug: str) -> dict[str, Any]:
    """Return branding for an org slug, falling back to default CosmicSec brand."""
    return _branding_cache.get(org_slug) or _branding_cache["default"]


def update_branding(org_slug: str, branding: dict[str, Any]) -> dict[str, Any]:
    """Store or update org branding data. Returns merged branding."""
    existing = _branding_cache.get(org_slug, {})
    merged = {**_branding_cache["default"], **existing, **branding}
    _branding_cache[org_slug] = merged
    return merged


async def _fetch_org_branding(org_slug: str) -> dict[str, Any] | None:
    """Fetch branding from org service (non-blocking, best-effort)."""
    if not _SAFE_ORG_SERVICE_URL:
        return None
    safe_slug = normalize_org_slug(org_slug)
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(
                f"{_SAFE_ORG_SERVICE_URL}/api/orgs/slug/{quote(safe_slug)}/branding"
            )
            if resp.status_code == 200:
                data = resp.json()
                update_branding(safe_slug, data.get("branding") or data)
                return _branding_cache[safe_slug]
    except Exception as exc:
        logger.debug(
            "Could not fetch org branding for '%s': %s",
            sanitize_for_log(safe_slug),
            sanitize_for_log(exc),
        )
    return None


def to_css_variables(branding: dict[str, Any]) -> str:
    """Convert branding dict to CSS custom properties block."""
    lines = [":root {"]
    if primary := branding.get("primary_color"):
        lines.append(f"  --color-primary: {primary};")
    if accent := branding.get("accent_color"):
        lines.append(f"  --color-accent: {accent};")
    if bg := branding.get("background_color"):
        lines.append(f"  --color-background: {bg};")
    if custom := branding.get("custom_css"):
        lines.append(custom)
    lines.append("}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class WhiteLabelMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware that reads ``X-Org-Slug`` request header and
    attaches org branding metadata headers to the response.

    Frontend SPA reads these headers and applies CSS variables on mount.
    """

    async def dispatch(self, request: Request, call_next):
        org_slug = normalize_org_slug(request.headers.get("X-Org-Slug", "default"))
        branding = get_branding(org_slug)

        # Background refresh from org service if slug not cached
        if org_slug != "default" and org_slug not in _branding_cache:
            await _fetch_org_branding(org_slug)
            branding = get_branding(org_slug)

        response: Response = await call_next(request)

        # Inject lightweight branding headers
        response.headers["X-Org-Name"] = branding.get("name", "CosmicSec")
        response.headers["X-Primary-Color"] = branding.get("primary_color", "#6366f1")
        response.headers["X-Logo-URL"] = branding.get("logo_url", "/static/logo.svg")
        return response


# ---------------------------------------------------------------------------
# Branding API routes (mounted by API gateway)
# ---------------------------------------------------------------------------


def mount_branding_routes(app: FastAPI) -> None:
    @app.get("/api/branding/{org_slug}")
    async def get_org_branding(org_slug: str) -> JSONResponse:
        """
        Return org branding including CSS variables for frontend theming.
        Frontend calls this on first load and applies CSS custom properties.
        """
        safe_slug = normalize_org_slug(org_slug)
        branding = get_branding(safe_slug)
        # Attempt live refresh
        if safe_slug != "default":
            try:
                refreshed = await _fetch_org_branding(safe_slug)
                if refreshed:
                    branding = refreshed
            except Exception:
                logger.debug(
                    "Branding refresh failed for org %s", sanitize_for_log(safe_slug), exc_info=True
                )

        return JSONResponse(
            {
                "org_slug": safe_slug,
                "branding": branding,
                "css_variables": to_css_variables(branding),
                "theme": {
                    "mode": "dark",
                    "primary": branding.get("primary_color", "#6366f1"),
                    "accent": branding.get("accent_color", "#06b6d4"),
                    "background": branding.get("background_color", "#0f172a"),
                },
            }
        )

    @app.put("/api/branding/{org_slug}")
    async def update_org_branding(org_slug: str, request: Request) -> JSONResponse:
        """Update org branding (admin only — validated by API gateway auth middleware)."""
        safe_slug = normalize_org_slug(org_slug)
        body = await request.json()
        branding = update_branding(safe_slug, body)
        return JSONResponse({"org_slug": safe_slug, "branding": branding})
