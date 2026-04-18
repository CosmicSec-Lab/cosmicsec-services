"""CosmicSec Egress Service.

Central service for reusable outbound identity/profile strategy resolution and
optional Tor/proxy-based HTTP probing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

from services.common.egress import EgressOptions, EgressStrategyError, create_async_client

app = FastAPI(title="CosmicSec Egress Service", version="1.0.0")


class StrategyRequest(BaseModel):
    target_url: str | None = None
    use_proxy_pool: bool = False
    proxy_url: str | None = None
    rotate_identity: bool = False
    client_profile: str | None = None
    use_tor: bool = False
    tor_mode: str | None = None


class ProbeRequest(StrategyRequest):
    method: str = "GET"
    timeout_seconds: float = 15.0


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "healthy",
        "service": "egress-service",
        "timestamp": datetime.now(tz=UTC).isoformat(),
    }


@app.post("/strategy/resolve")
async def resolve_strategy(payload: StrategyRequest) -> dict[str, Any]:
    options = EgressOptions(
        use_proxy_pool=payload.use_proxy_pool,
        proxy_url=payload.proxy_url,
        rotate_identity=payload.rotate_identity,
        client_profile=payload.client_profile,
        use_tor=payload.use_tor,
        tor_mode=payload.tor_mode if payload.tor_mode in {"enabled", "disabled", "auto"} else None,
    )
    try:
        _, strategy = create_async_client(
            "egress-service",
            target_url=payload.target_url,
            options=options,
            timeout=5.0,
        )
        return {
            "status": "ok",
            "strategy": {
                "profile": strategy.get("profile"),
                "proxy_enabled": bool(strategy.get("proxy_url")),
                "tor_enabled": bool(strategy.get("tor_enabled")),
                "tor_mode": strategy.get("tor_mode"),
                "rotating_identity": bool(strategy.get("rotating_identity")),
            },
        }
    except EgressStrategyError as exc:
        return {"status": "rejected", "reason": str(exc)}


@app.post("/probe")
async def probe(payload: ProbeRequest) -> dict[str, Any]:
    if not payload.target_url:
        return {"status": "rejected", "reason": "target_url is required"}

    options = EgressOptions(
        use_proxy_pool=payload.use_proxy_pool,
        proxy_url=payload.proxy_url,
        rotate_identity=payload.rotate_identity,
        client_profile=payload.client_profile,
        use_tor=payload.use_tor,
        tor_mode=payload.tor_mode if payload.tor_mode in {"enabled", "disabled", "auto"} else None,
    )

    try:
        client, strategy = create_async_client(
            "egress-service",
            target_url=payload.target_url,
            options=options,
            timeout=payload.timeout_seconds,
            follow_redirects=True,
        )
    except EgressStrategyError as exc:
        return {"status": "rejected", "reason": str(exc)}

    async with client:
        try:
            response = await client.request(payload.method.upper(), payload.target_url)
            return {
                "status": "ok",
                "target_url": payload.target_url,
                "http_status": response.status_code,
                "final_url": str(response.url),
                "content_type": response.headers.get("content-type"),
                "probe_size": len(response.content),
                "strategy": {
                    "profile": strategy.get("profile"),
                    "proxy_enabled": bool(strategy.get("proxy_url")),
                    "tor_enabled": bool(strategy.get("tor_enabled")),
                    "tor_mode": strategy.get("tor_mode"),
                    "rotating_identity": bool(strategy.get("rotating_identity")),
                },
            }
        except httpx.HTTPError as exc:
            return {
                "status": "error",
                "target_url": payload.target_url,
                "error": str(exc),
                "strategy": {
                    "profile": strategy.get("profile"),
                    "proxy_enabled": bool(strategy.get("proxy_url")),
                    "tor_enabled": bool(strategy.get("tor_enabled")),
                    "tor_mode": strategy.get("tor_mode"),
                    "rotating_identity": bool(strategy.get("rotating_identity")),
                },
            }
