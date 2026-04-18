"""
CosmicSec Recon Service — Phase S.1: Redis caching for expensive OSINT lookups.

Cache TTLs:
  DNS lookups:       1 hour
  Shodan results:   24 hours
  VirusTotal:       12 hours
  crt.sh CT logs:    6 hours
  RDAP/WHOIS:        6 hours
"""

import contextlib
import hashlib
import json
import os
import re
import socket
from asyncio import gather
from datetime import UTC, datetime
from urllib.parse import quote, urlparse

import httpx
from fastapi import FastAPI
from pydantic import BaseModel
from starlette.responses import PlainTextResponse

from services.common.egress import EgressOptions, EgressStrategyError, create_async_client

try:
    import redis as _redis_module

    _sync_redis = _redis_module.from_url(
        f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}/0",
        decode_responses=True,
        socket_connect_timeout=2,
    )
    # Validate connection
    _sync_redis.ping()
    _CACHE_ENABLED = True
except Exception:
    _sync_redis = None
    _CACHE_ENABLED = False


def _cache_get(key: str) -> dict | None:
    if not _CACHE_ENABLED or _sync_redis is None:
        return None
    try:
        raw = _sync_redis.get(key)
        return json.loads(raw) if raw else None
    except Exception:
        return None


def _cache_set(key: str, value: dict, ttl_seconds: int) -> None:
    if not _CACHE_ENABLED or _sync_redis is None:
        return
    with contextlib.suppress(Exception):
        _sync_redis.setex(key, ttl_seconds, json.dumps(value, default=str))


def _cache_key(prefix: str, target: str) -> str:
    return f"recon:{prefix}:{hashlib.sha256(target.lower().encode()).hexdigest()}"


app = FastAPI(title="CosmicSec Recon Service", version="1.0.0")


class ReconRequest(BaseModel):
    target: str
    use_proxy_pool: bool = False
    proxy_url: str | None = None
    rotate_identity: bool = False
    client_profile: str | None = None
    use_tor: bool = False
    tor_mode: str | None = None


_SAFE_HOST_RE = re.compile(r"^[a-z0-9.-]+$", re.IGNORECASE)


def _normalize_target(target: str) -> str:
    value = target.strip()
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.hostname or value
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or not _SAFE_HOST_RE.fullmatch(value):
        return "invalid-target"
    return value


def _dns_recon(target: str) -> dict:
    cache_key = _cache_key("dns", target)
    cached = _cache_get(cache_key)
    if cached is not None:
        return {**cached, "cached": True}

    result: dict = {"target": target, "ips": [], "errors": []}
    try:
        _, _, ips = socket.gethostbyname_ex(target)
        result["ips"] = sorted(set(ips))
    except OSError as exc:
        result["errors"].append(str(exc))

    _cache_set(cache_key, result, ttl_seconds=3600)  # 1 hour
    return result


async def _shodan_lookup(client: httpx.AsyncClient, target: str) -> dict:
    cache_key = _cache_key("shodan", target)
    cached = _cache_get(cache_key)
    if cached is not None:
        return {**cached, "cached": True}

    api_key = os.getenv("SHODAN_API_KEY")
    if not api_key:
        return {"enabled": False, "reason": "SHODAN_API_KEY not configured"}

    url = f"https://api.shodan.io/dns/domain/{quote(target)}"
    try:
        response = await client.get(url, params={"key": api_key}, timeout=8.0)
        response.raise_for_status()
        body = response.json()
        result = {
            "enabled": True,
            "subdomains": body.get("subdomains", [])[:25],
            "data_preview": body.get("data", [])[:5],
        }
        _cache_set(cache_key, result, ttl_seconds=86400)  # 24 hours
        return result
    except (httpx.HTTPError, ValueError):
        return {"enabled": True, "error": "Shodan lookup failed"}


async def _virustotal_lookup(client: httpx.AsyncClient, target: str) -> dict:
    cache_key = _cache_key("virustotal", target)
    cached = _cache_get(cache_key)
    if cached is not None:
        return {**cached, "cached": True}

    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"enabled": False, "reason": "VIRUSTOTAL_API_KEY not configured"}

    url = f"https://www.virustotal.com/api/v3/domains/{quote(target)}"
    headers = {"x-apikey": api_key}
    try:
        response = await client.get(url, headers=headers, timeout=8.0)
        response.raise_for_status()
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        result = {"enabled": True, "analysis_stats": stats}
        _cache_set(cache_key, result, ttl_seconds=43200)  # 12 hours
        return result
    except (httpx.HTTPError, ValueError):
        return {"enabled": True, "error": "VirusTotal lookup failed"}


async def _crtsh_lookup(client: httpx.AsyncClient, target: str) -> dict:
    """Legacy-inspired subdomain discovery using certificate transparency logs."""
    cache_key = _cache_key("crtsh", target)
    cached = _cache_get(cache_key)
    if cached is not None:
        return {**cached, "cached": True}

    url = "https://crt.sh/"
    try:
        response = await client.get(url, params={"q": f"%.{target}", "output": "json"}, timeout=8.0)
        response.raise_for_status()
        rows = response.json()
        names = set()
        for row in rows[:200]:
            value = row.get("name_value", "")
            for name in str(value).splitlines():
                clean = name.strip().lower().lstrip("*.")
                if clean and clean.endswith(target.lower()):
                    names.add(clean)
        result = {"enabled": True, "subdomains": sorted(names)[:50]}
        _cache_set(cache_key, result, ttl_seconds=21600)  # 6 hours
        return result
    except (httpx.HTTPError, ValueError):
        return {"enabled": True, "error": "crt.sh lookup failed"}


async def _rdap_lookup(client: httpx.AsyncClient, target: str) -> dict:
    """Modern WHOIS-style metadata via RDAP without extra dependencies."""
    cache_key = _cache_key("rdap", target)
    cached = _cache_get(cache_key)
    if cached is not None:
        return {**cached, "cached": True}

    try:
        response = await client.get(f"https://rdap.org/domain/{quote(target)}", timeout=8.0)
        response.raise_for_status()
        body = response.json()
        events = body.get("events", [])
        nameservers = [ns.get("ldhName") for ns in body.get("nameservers", []) if ns.get("ldhName")]
        result = {
            "enabled": True,
            "handle": body.get("handle"),
            "status": body.get("status", []),
            "events_preview": events[:3],
            "nameservers": nameservers[:10],
        }
        _cache_set(cache_key, result, ttl_seconds=21600)  # 6 hours
        return result
    except (httpx.HTTPError, ValueError):
        return {"enabled": True, "error": "RDAP lookup failed"}


@app.get("/health")
def health() -> dict:
    return {
        "status": "healthy",
        "service": "recon-service",
        "cache_enabled": _CACHE_ENABLED,
    }


@app.get("/metrics")
def metrics() -> PlainTextResponse:
    body = (
        "# HELP cosmicsec_recon_service_up Recon service health status\n"
        "# TYPE cosmicsec_recon_service_up gauge\n"
        "cosmicsec_recon_service_up 1\n"
    )
    return PlainTextResponse(content=body, media_type="text/plain; version=0.0.4")


@app.get("/cache/stats")
def cache_stats() -> dict:
    """Return cache health and (if Redis available) info."""
    if not _CACHE_ENABLED or _sync_redis is None:
        return {"enabled": False, "reason": "Redis unavailable"}
    try:
        info = _sync_redis.info("memory")
        return {
            "enabled": True,
            "used_memory_human": info.get("used_memory_human"),
            "keys": _sync_redis.dbsize(),
        }
    except Exception:
        return {"enabled": False, "error": "Cache stats unavailable"}


@app.post("/recon")
async def run_recon(payload: ReconRequest) -> dict:
    target = _normalize_target(payload.target)
    if target == "invalid-target":
        return {
            "status": "rejected",
            "reason": "target must be a valid hostname or domain",
            "timestamp": datetime.now(tz=UTC).isoformat(),
        }

    dns = _dns_recon(target)

    try:
        client, network = create_async_client(
            "recon-service",
            target_url=f"http://{target}",
            options=EgressOptions(
                use_proxy_pool=payload.use_proxy_pool,
                proxy_url=payload.proxy_url,
                rotate_identity=payload.rotate_identity,
                client_profile=payload.client_profile,
                use_tor=payload.use_tor,
                tor_mode=payload.tor_mode
                if payload.tor_mode in {"enabled", "disabled", "auto"}
                else None,
            ),
            timeout=10.0,
        )
    except EgressStrategyError as exc:
        return {
            "status": "rejected",
            "reason": str(exc),
            "timestamp": datetime.now(tz=UTC).isoformat(),
        }
    except Exception:
        return {
            "status": "rejected",
            "reason": "Unable to initialize outbound client for selected network strategy",
            "timestamp": datetime.now(tz=UTC).isoformat(),
        }

    async with client:
        shodan, virustotal, crtsh, rdap = await gather(
            _shodan_lookup(client, target),
            _virustotal_lookup(client, target),
            _crtsh_lookup(client, target),
            _rdap_lookup(client, target),
        )

    return {
        "target": target,
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "dns": dns,
        "shodan": shodan,
        "virustotal": virustotal,
        "crtsh": crtsh,
        "rdap": rdap,
        "network_profile": {
            "profile": network.get("profile"),
            "proxy_enabled": bool(network.get("proxy_url")),
            "tor_enabled": bool(network.get("tor_enabled")),
            "tor_mode": network.get("tor_mode"),
            "rotating_identity": bool(network.get("rotating_identity")),
        },
        "findings": [
            {
                "source": "dns",
                "summary": f"Resolved addresses for {target}: {', '.join(dns['ips']) if dns['ips'] else 'none'}",
            },
            {"source": "osint", "summary": f"External intelligence checks completed for {target}"},
            {
                "source": "network-strategy",
                "summary": "Applied configured proxy / identity strategy for outbound recon requests.",
            },
            {
                "source": "legacy-merge",
                "summary": "Merged legacy CT-log and WHOIS-style domain intelligence into hybrid recon flow.",
            },
        ],
    }
