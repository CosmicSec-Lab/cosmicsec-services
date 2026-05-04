"""Shared outbound egress strategy for CosmicSec services.

Provides reusable proxy, Tor, and identity/profile rotation controls for HTTP clients.
"""

from __future__ import annotations

import ipaddress
import os
import random
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlparse

import httpx

DEFAULT_USER_AGENTS = {
    "desktop_chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "desktop_firefox": "Mozilla/5.0 (X11; Linux x86_64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "android_mobile": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36",
    "ios_safari": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
}

DEVICE_PROFILE_HEADERS = {
    "desktop_chrome": {
        "Sec-CH-UA-Platform": "Windows",
        "X-CosmicSec-Device": "desktop",
        "X-CosmicSec-Profile": "desktop_chrome",
    },
    "desktop_firefox": {
        "Sec-CH-UA-Platform": "Linux",
        "X-CosmicSec-Device": "desktop",
        "X-CosmicSec-Profile": "desktop_firefox",
    },
    "android_mobile": {
        "Sec-CH-UA-Platform": "Android",
        "X-CosmicSec-Device": "mobile",
        "X-CosmicSec-Profile": "android_mobile",
    },
    "ios_safari": {
        "Sec-CH-UA-Platform": "iOS",
        "X-CosmicSec-Device": "mobile",
        "X-CosmicSec-Profile": "ios_safari",
    },
}


@dataclass
class EgressOptions:
    use_proxy_pool: bool = False
    proxy_url: str | None = None
    rotate_identity: bool = False
    client_profile: str | None = None
    use_tor: bool = False
    tor_mode: Literal["enabled", "disabled", "auto"] | None = None


class EgressStrategyError(ValueError):
    """Raised when selected egress strategy is invalid for a target."""


def _parse_csv_env(name: str) -> list[str]:
    raw = os.getenv(name, "").strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _service_env_key(service_name: str, suffix: str) -> str:
    normalized = service_name.upper().replace("-", "_")
    return f"COSMICSEC_{normalized}_{suffix}"


def _is_local_or_private_host(hostname: str) -> bool:
    host = (hostname or "").strip().lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def is_onion_hostname(hostname: str) -> bool:
    return (hostname or "").strip().lower().endswith(".onion")


def _pick_client_profile(service_name: str, options: EgressOptions) -> str:
    if options.client_profile in DEFAULT_USER_AGENTS:
        return options.client_profile

    env_profile = os.getenv(_service_env_key(service_name, "CLIENT_PROFILE"), "").strip()
    if env_profile in DEFAULT_USER_AGENTS:
        return env_profile

    global_profile = os.getenv("COSMICSEC_EGRESS_CLIENT_PROFILE", "").strip()
    if global_profile in DEFAULT_USER_AGENTS:
        return global_profile

    profiles = list(DEFAULT_USER_AGENTS.keys())
    if options.rotate_identity:
        return random.choice(profiles)
    return "desktop_chrome"


def _pick_user_agent(service_name: str, profile: str, rotate_identity: bool) -> str:
    service_pool = _parse_csv_env(_service_env_key(service_name, "USER_AGENT_POOL"))
    if service_pool:
        return random.choice(service_pool) if rotate_identity else service_pool[0]

    global_pool = _parse_csv_env("COSMICSEC_GLOBAL_USER_AGENT_POOL")
    if global_pool:
        return random.choice(global_pool) if rotate_identity else global_pool[0]

    return DEFAULT_USER_AGENTS.get(profile, DEFAULT_USER_AGENTS["desktop_chrome"])


def _resolve_tor_mode(
    service_name: str, options: EgressOptions
) -> Literal["enabled", "disabled", "auto"]:
    requested = (options.tor_mode or "").strip().lower()
    if requested in {"enabled", "disabled", "auto"}:
        return requested  # type: ignore[return-value]

    service_mode = os.getenv(_service_env_key(service_name, "TOR_MODE"), "").strip().lower()
    if service_mode in {"enabled", "disabled", "auto"}:
        return service_mode  # type: ignore[return-value]

    global_mode = os.getenv("COSMICSEC_GLOBAL_TOR_MODE", "").strip().lower()
    if global_mode in {"enabled", "disabled", "auto"}:
        return global_mode  # type: ignore[return-value]

    if options.use_tor or _as_bool(os.getenv(_service_env_key(service_name, "USE_TOR"), "")):
        return "enabled"

    return "auto"


def _pick_proxy(service_name: str, options: EgressOptions, *, tor_enabled: bool) -> str | None:
    if tor_enabled:
        service_tor = os.getenv(_service_env_key(service_name, "TOR_PROXY_URL"), "").strip()
        if service_tor:
            return service_tor
        global_tor = os.getenv("COSMICSEC_GLOBAL_TOR_PROXY_URL", "").strip()
        return global_tor or None

    if options.proxy_url:
        return options.proxy_url.strip() or None

    use_pool = options.use_proxy_pool or os.getenv(
        _service_env_key(service_name, "USE_PROXY_POOL"), ""
    ).lower() in {"1", "true", "yes", "on"}

    if use_pool:
        service_pool = _parse_csv_env(_service_env_key(service_name, "PROXY_POOL"))
        pool = service_pool or _parse_csv_env("COSMICSEC_GLOBAL_PROXY_POOL")
        if pool:
            return random.choice(pool) if options.rotate_identity else pool[0]

    return None


def resolve_egress_strategy(
    service_name: str,
    *,
    target_url: str | None = None,
    options: EgressOptions | None = None,
) -> dict[str, Any]:
    opts = options or EgressOptions()
    parsed = urlparse(target_url or "")
    hostname = (parsed.hostname or "").strip().lower()
    tor_mode = _resolve_tor_mode(service_name, opts)
    tor_enabled = tor_mode == "enabled" or (
        tor_mode == "auto" and bool(hostname) and is_onion_hostname(hostname)
    )

    profile = _pick_client_profile(service_name, opts)
    user_agent = _pick_user_agent(service_name, profile, opts.rotate_identity)
    proxy_url = _pick_proxy(service_name, opts, tor_enabled=tor_enabled)

    # Never send local/private targets through Tor/proxy routing.
    if hostname and _is_local_or_private_host(hostname):
        proxy_url = None
        tor_enabled = False
        tor_mode = "disabled"

    if hostname and is_onion_hostname(hostname) and not tor_enabled:
        raise EgressStrategyError("onion target requires Tor-enabled egress strategy")

    if tor_enabled and not proxy_url:
        raise EgressStrategyError("Tor-enabled strategy requires a configured Tor proxy URL")

    return {
        "service": service_name,
        "profile": profile,
        "user_agent": user_agent,
        "proxy_url": proxy_url,
        "tor_enabled": tor_enabled,
        "tor_mode": tor_mode,
        "rotating_identity": bool(opts.rotate_identity),
    }


def create_async_client(
    service_name: str,
    *,
    target_url: str | None = None,
    options: EgressOptions | None = None,
    timeout: float | httpx.Timeout | None = None,
    follow_redirects: bool = False,
    verify: bool = True,
    headers: dict[str, str] | None = None,
) -> tuple[httpx.AsyncClient, dict[str, Any]]:
    strategy = resolve_egress_strategy(service_name, target_url=target_url, options=options)

    profile = str(strategy.get("profile") or "desktop_chrome")
    default_headers = {
        "User-Agent": str(strategy.get("user_agent") or DEFAULT_USER_AGENTS["desktop_chrome"]),
        "Accept": "application/json, text/plain, */*",
    }
    default_headers.update(
        DEVICE_PROFILE_HEADERS.get(profile, DEVICE_PROFILE_HEADERS["desktop_chrome"])
    )
    if headers:
        default_headers.update(headers)

    client_kwargs: dict[str, Any] = {
        "headers": default_headers,
        "follow_redirects": follow_redirects,
        "verify": verify,
    }
    if timeout is not None:
        client_kwargs["timeout"] = timeout
    if isinstance(strategy.get("proxy_url"), str) and strategy["proxy_url"]:
        client_kwargs["proxy"] = strategy["proxy_url"]

    return httpx.AsyncClient(**client_kwargs), strategy
