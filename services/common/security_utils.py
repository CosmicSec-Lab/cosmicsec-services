"""Shared security helpers used across CosmicSec services."""

from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path
from urllib.parse import urlparse

_LOG_UNSAFE_RE = re.compile(r"[\r\n\t\x00]")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_SCAN_ID_RE = re.compile(r"[^a-zA-Z0-9_-]+")


def sanitize_for_log(value: object, *, max_length: int = 256) -> str:
    """Return a log-safe scalar string without control characters."""
    text = str(value)
    text = _LOG_UNSAFE_RE.sub(" ", text).strip()
    if len(text) > max_length:
        return text[: max_length - 3] + "..."
    return text


def normalize_org_slug(value: str, *, default: str = "default") -> str:
    """Normalize org slugs to a strict lowercase token."""
    candidate = (value or "").strip().lower()
    if _SLUG_RE.fullmatch(candidate):
        return candidate
    return default


def sanitize_scan_id(value: str) -> str:
    """Convert scan identifiers into safe filename stems."""
    candidate = _SCAN_ID_RE.sub("_", (value or "").strip())
    candidate = candidate.strip("._-")
    return candidate[:80] or "report"


def _is_private_or_loopback(hostname: str) -> bool:
    """Best-effort check for local, private, or link-local addresses."""
    host = hostname.strip().strip("[]")
    if host in {"localhost", "localhost.localdomain"}:
        return True

    try:
        parsed = ipaddress.ip_address(host)
        return (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_reserved
            or parsed.is_multicast
        )
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return True

    for info in infos:
        ip_raw = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_raw)
        except ValueError:
            return True
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
        ):
            return True
    return False


def validate_outbound_url(
    url: str,
    *,
    allowed_hosts: set[str] | None = None,
    allow_private_hosts: bool = False,
    allow_onion_hosts: bool = False,
    require_https: bool = False,
) -> str | None:
    """Validate outbound URL for SSRF resistance and return normalized string."""
    value = (url or "").strip()
    if not value:
        return None

    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        return None
    if require_https and parsed.scheme != "https":
        return None

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return None

    is_onion = hostname.endswith(".onion")
    if is_onion and not allow_onion_hosts:
        return None

    if allowed_hosts:
        if hostname not in allowed_hosts:
            return None
    elif not allow_private_hosts and not is_onion and _is_private_or_loopback(hostname):
        return None

    return parsed.geturl()


def ensure_safe_child_path(base_dir: Path, filename: str) -> Path:
    """Build a path under base_dir and reject traversal attempts."""
    base_resolved = base_dir.resolve()
    target = (base_resolved / filename).resolve()
    if base_resolved not in target.parents and target != base_resolved:
        raise ValueError("Unsafe path outside report directory")
    return target
