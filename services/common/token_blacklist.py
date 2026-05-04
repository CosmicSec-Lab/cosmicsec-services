"""Token blacklist backed by Redis (with in-memory fallback).

Prevents use of revoked/expired JWT tokens before their natural expiry.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any

logger = logging.getLogger(__name__)

# ── Redis Client ───────────────────────────────────────────────
_redis_client: Any | None = None
try:
    import redis

    _redis_client = redis.from_url(
        f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}/1",
        decode_responses=True,
        socket_connect_timeout=2,
    )
    _redis_client.ping()
    _REDIS_AVAILABLE = True
except Exception:
    _REDIS_AVAILABLE = False

# ── In-Memory Fallback ────────────────────────────────────────
_blacklist: dict[str, float] = {}  # jti -> expiry_timestamp
_MAX_IN_MEMORY = 50_000  # Prevent unbounded growth

# ── Public API ─────────────────────────────────────────────────

def blacklist_token(jti: str, ttl_seconds: int = 86400) -> bool:
    """Add a token's JTI to the blacklist.

    Returns True on success, False on failure.
    """
    if _REDIS_AVAILABLE and _redis_client is not None:
        try:
            pipe = _redis_client.pipeline()
            pipe.setex(f"bl:{jti}", ttl_seconds, "1")
            pipe.execute()
            return True
        except Exception:
            logger.warning("Redis blacklist failed, using in-memory fallback", exc_info=True)

    # In-memory fallback
    if len(_blacklist) > _MAX_IN_MEMORY:
        _prune_expired()
    _blacklist[jti] = time.time() + ttl_seconds
    return True


def is_token_blacklisted(jti: str) -> bool:
    """Check whether a token JTI has been revoked."""
    if _REDIS_AVAILABLE and _redis_client is not None:
        try:
            return _redis_client.exists(f"bl:{jti}") == 1
        except Exception:
            pass

    # In-memory fallback
    expiry = _blacklist.get(jti)
    if expiry is None:
        return False
    if expiry < time.time():
        _blacklist.pop(jti, None)
        return False
    return True


def invalidate_user_tokens(user_id: str, ttl_seconds: int = 86400) -> int:
    """Blacklist all tokens for a given user (requires user_id -> jti mapping).

    Returns count of tokens blacklisted.
    """
    if _REDIS_AVAILABLE and _redis_client is not None:
        try:
            pattern = f"bl:user:{user_id}:*"
            count = 0
            cursor = 0
            while True:
                cursor, keys = _redis_client.scan(cursor=cursor, match=pattern, count=100)
                if keys:
                    pipe = _redis_client.pipeline()
                    for key in keys:
                        pipe.setex(key, ttl_seconds, "1")
                    pipe.execute()
                    count += len(keys)
                if cursor == 0:
                    break
            return count
        except Exception:
            logger.warning("Redis user token invalidation failed", exc_info=True)
    return 0


# ── Internal Helpers ──────────────────────────────────────────

def _prune_expired() -> None:
    now = time.time()
    to_remove = [jti for jti, exp in _blacklist.items() if exp < now]
    for jti in to_remove:
        _blacklist.pop(jti, None)
