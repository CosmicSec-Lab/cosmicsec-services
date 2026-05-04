"""Rate limiting middleware for FastAPI services.

Provides sliding-window rate limiting with Redis backend and in-memory fallback.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

import redis as _redis_module

# ── Rate Limit Storage ─────────────────────────────────────────
_redis: Any | None = None
try:
    import os

    _redis = _redis_module.from_url(
        f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}/2",
        decode_responses=True,
        socket_connect_timeout=2,
    )
    _redis.ping()
    _REDIS_OK = True
except Exception:
    _REDIS_OK = False

_memory_limits: dict[str, list[float]] = defaultdict(list)
_MAX_MEMORY_KEYS = 10_000

# ── Core Rate Limiter ──────────────────────────────────────────

def is_rate_limited(
    key: str,
    max_requests: int = 10,
    window_seconds: int = 60,
) -> tuple[bool, dict[str, int]]:
    """Check if a key has exceeded its rate limit.

    Args:
        key: Unique identifier (e.g. "login:1.2.3.4" or "2fa:user@example.com").
        max_requests: Maximum allowed requests within the window.
        window_seconds: Sliding window duration in seconds.

    Returns:
        (is_limited, info_dict) where info_dict has limit, remaining, retry_after.
    """
    if _REDIS_OK and _redis is not None:
        return _check_redis(key, max_requests, window_seconds)
    return _check_memory(key, max_requests, window_seconds)


def _check_redis(
    key: str, max_requests: int, window_seconds: int
) -> tuple[bool, dict[str, int]]:
    now = time.time()
    redis_key = f"rl:{key}"
    try:
        pipe = _redis.pipeline()
        pipe.zremrangebyscore(redis_key, 0, now - window_seconds)
        pipe.zadd(redis_key, {str(now): now})
        pipe.zcard(redis_key)
        pipe.expire(redis_key, window_seconds + 1)
        _, _, count, _ = pipe.execute()

        remaining = max(0, max_requests - int(count))
        if int(count) > max_requests:
            oldest = _redis.zrange(redis_key, 0, 0, withscores=True)
            retry_after = int(oldest[0][1] + window_seconds - now) if oldest else window_seconds
            return True, {"limit": max_requests, "remaining": 0, "retry_after": max(retry_after, 1)}

        return False, {"limit": max_requests, "remaining": remaining, "retry_after": 0}
    except Exception:
        return _check_memory(key, max_requests, window_seconds)


def _check_memory(
    key: str, max_requests: int, window_seconds: int
) -> tuple[bool, dict[str, int]]:
    now = time.time()
    timestamps = _memory_limits[key]
    cutoff = now - window_seconds
    _memory_limits[key] = [ts for ts in timestamps if ts > cutoff]

    if len(_memory_limits[key]) > _MAX_MEMORY_KEYS:
        _memory_limits[key] = _memory_limits[key][-_MAX_MEMORY_KEYS:]

    if len(_memory_limits[key]) >= max_requests:
        oldest = min(_memory_limits[key]) if _memory_limits[key] else now
        retry_after = int(oldest + window_seconds - now) + 1
        return True, {"limit": max_requests, "remaining": 0, "retry_after": max(retry_after, 1)}

    _memory_limits[key].append(now)
    remaining = max(0, max_requests - len(_memory_limits[key]))
    return False, {"limit": max_requests, "remaining": remaining, "retry_after": 0}


def reset_limit(key: str) -> None:
    """Remove rate limit data for a key."""
    if _REDIS_OK and _redis is not None:
        try:
            _redis.delete(f"rl:{key}")
        except Exception:
            pass
    _memory_limits.pop(key, None)
