"""
Login rate limiter for the CosmicSec Authentication Service.

Provides IP-based rate limiting and email-based account lockout
to protect against brute-force login attacks.
"""

import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

# Limits
IP_MAX_ATTEMPTS = 5
IP_WINDOW_SECONDS = 15 * 60  # 15 minutes

EMAIL_MAX_ATTEMPTS = 10
EMAIL_LOCKOUT_SECONDS = 30 * 60  # 30 minutes


class LoginRateLimiter:
    """Track failed login attempts and enforce rate limits.

    Tries Redis (``redis.asyncio``) first; falls back to an in-memory
    counter that is protected by a threading lock.
    """

    def __init__(self) -> None:
        self._redis = None
        self._lock = threading.Lock()
        # In-memory fallback: key -> list of timestamps
        self._attempts: dict[str, list[float]] = {}
        self._connect_redis()

    # ------------------------------------------------------------------
    # Redis bootstrap
    # ------------------------------------------------------------------
    def _connect_redis(self) -> None:
        try:
            import redis.asyncio as aioredis

            redis_url = os.getenv("REDIS_URL", "").strip()
            if redis_url:
                self._redis = aioredis.from_url(
                    redis_url,
                    decode_responses=True,
                    socket_connect_timeout=1,
                    socket_timeout=1,
                )
            else:
                self._redis = aioredis.Redis(
                    host=os.getenv("REDIS_HOST", "redis"),
                    port=int(os.getenv("REDIS_PORT", "6379")),
                    password=os.getenv("REDIS_PASSWORD"),
                    decode_responses=True,
                    socket_connect_timeout=1,
                    socket_timeout=1,
                )
        except Exception:
            self._redis = None
            logger.warning(
                "redis.asyncio unavailable – login rate limiter using in-memory fallback"
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def check_rate_limit(self, ip: str, email: str) -> tuple[bool, str | None]:
        """Return ``(allowed, error_message)``.

        *allowed* is ``False`` when the request should be rejected.
        """
        if self._redis is not None:
            return await self._check_redis(ip, email)
        return self._check_memory(ip, email)

    async def record_failed_attempt(self, ip: str, email: str) -> None:
        if self._redis is not None:
            await self._record_redis(ip, email)
        else:
            self._record_memory(ip, email)

    async def reset_on_success(self, ip: str, email: str) -> None:
        if self._redis is not None:
            await self._reset_redis(ip, email)
        else:
            self._reset_memory(ip, email)

    # ------------------------------------------------------------------
    # Redis implementation
    # ------------------------------------------------------------------
    @staticmethod
    def _ip_key(ip: str) -> str:
        return f"rate:ip:{ip}"

    @staticmethod
    def _email_key(email: str) -> str:
        return f"rate:email:{email}"

    async def _check_redis(self, ip: str, email: str) -> tuple[bool, str | None]:
        try:
            ip_count = await self._redis.get(self._ip_key(ip))
            if ip_count is not None and int(ip_count) >= IP_MAX_ATTEMPTS:
                ttl = await self._redis.ttl(self._ip_key(ip))
                retry_after = max(ttl, 1)
                return False, f"Too many login attempts from this IP. Retry after {retry_after}s."

            email_count = await self._redis.get(self._email_key(email))
            if email_count is not None and int(email_count) >= EMAIL_MAX_ATTEMPTS:
                ttl = await self._redis.ttl(self._email_key(email))
                retry_after = max(ttl, 1)
                return (
                    False,
                    f"Account temporarily locked due to too many failed attempts. Retry after {retry_after}s.",
                )
        except Exception:
            # If Redis fails mid-flight, allow the request through
            logger.warning("Redis error during rate-limit check; allowing request")
        return True, None

    async def _record_redis(self, ip: str, email: str) -> None:
        try:
            pipe = self._redis.pipeline()
            pipe.incr(self._ip_key(ip))
            pipe.expire(self._ip_key(ip), IP_WINDOW_SECONDS)
            pipe.incr(self._email_key(email))
            pipe.expire(self._email_key(email), EMAIL_LOCKOUT_SECONDS)
            await pipe.execute()
        except Exception:
            logger.warning("Redis error recording failed login attempt")

    async def _reset_redis(self, ip: str, email: str) -> None:
        try:
            await self._redis.delete(self._ip_key(ip), self._email_key(email))
        except Exception:
            logger.warning("Redis error resetting rate-limit counters")

    # ------------------------------------------------------------------
    # In-memory implementation (thread-safe)
    # ------------------------------------------------------------------
    def _purge_expired(self, key: str, window: float) -> list[float]:
        """Remove timestamps older than *window* seconds and return the rest."""
        now = time.monotonic()
        timestamps = self._attempts.get(key, [])
        valid = [ts for ts in timestamps if now - ts < window]
        if valid:
            self._attempts[key] = valid
        else:
            self._attempts.pop(key, None)
        return valid

    def _check_memory(self, ip: str, email: str) -> tuple[bool, str | None]:
        with self._lock:
            ip_key = f"ip:{ip}"
            ip_ts = self._purge_expired(ip_key, IP_WINDOW_SECONDS)
            if len(ip_ts) >= IP_MAX_ATTEMPTS:
                oldest = ip_ts[0]
                retry_after = int(IP_WINDOW_SECONDS - (time.monotonic() - oldest)) + 1
                return False, f"Too many login attempts from this IP. Retry after {retry_after}s."

            email_key = f"email:{email}"
            email_ts = self._purge_expired(email_key, EMAIL_LOCKOUT_SECONDS)
            if len(email_ts) >= EMAIL_MAX_ATTEMPTS:
                oldest = email_ts[0]
                retry_after = int(EMAIL_LOCKOUT_SECONDS - (time.monotonic() - oldest)) + 1
                return (
                    False,
                    f"Account temporarily locked due to too many failed attempts. Retry after {retry_after}s.",
                )

        return True, None

    def _record_memory(self, ip: str, email: str) -> None:
        now = time.monotonic()
        with self._lock:
            self._attempts.setdefault(f"ip:{ip}", []).append(now)
            self._attempts.setdefault(f"email:{email}", []).append(now)

    def _reset_memory(self, ip: str, email: str) -> None:
        with self._lock:
            self._attempts.pop(f"ip:{ip}", None)
            self._attempts.pop(f"email:{email}", None)
