"""Static continuity response profiles for hybrid runtime fallback paths."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from fastapi import Request

StaticProfile = Dict[str, Any]


def auth_login_profile(request: Request, payload: Optional[Dict[str, Any]]) -> StaticProfile:
    email = (payload or {}).get("email", "demo@cosmicsec.local")
    return {
        "status": "preview_auth",
        "access_token": "demo-preview-token",
        "refresh_token": "demo-preview-refresh-token",
        "token_type": "bearer",
        "expires_in": 1800,
        "preview_user": {"email": email, "role": "demo_viewer"},
        "next_action": "Use demo mode for preview auth or recover auth service for full login.",
    }


def scan_create_profile(_: Request, payload: Optional[Dict[str, Any]]) -> StaticProfile:
    return {
        "id": f"fallback-{int(time.time())}",
        "target": (payload or {}).get("target", "unknown"),
        "status": "queued_fallback",
        "message": "Static disaster-control scan queue accepted request for continuity.",
        "next_action": "Track queue and re-run full scan when dynamic services recover.",
        "runbook": "SOC-DR-SCAN-001",
    }


def recon_lookup_profile(_: Request, payload: Optional[Dict[str, Any]]) -> StaticProfile:
    target = (payload or {}).get("target", "unknown")
    return {
        "target": target,
        "timestamp": time.time(),
        "findings": [
            {"source": "static", "summary": "Dynamic recon unavailable. Returned fallback preview only."}
        ],
        "advisory": "Run full recon once dynamic services recover.",
        "runbook": "SOC-DR-RECON-001",
    }


def ai_health_profile(_: Request, __: Optional[Dict[str, Any]]) -> StaticProfile:
    return {
        "status": "degraded",
        "service": "ai-service",
        "capabilities": {"dynamic_inference": False, "fallback_profiles": True},
        "next_action": "Use deterministic static guidance until AI service recovers.",
        "runbook": "SOC-DR-AI-001",
    }


STATIC_PROFILES = {
    "auth_login": auth_login_profile,
    "scan_create": scan_create_profile,
    "recon_lookup": recon_lookup_profile,
    "ai_health": ai_health_profile,
}

