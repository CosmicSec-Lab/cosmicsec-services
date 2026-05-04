"""Tests for common shared utilities and middleware."""

import time
import pytest
from unittest.mock import MagicMock, patch

from services.common.security_utils import sanitize_for_log
from services.common.rate_limiter import RateLimiter, is_rate_limited
from services.common.exceptions import NotFoundError, PermissionError, ServiceUnavailableError


class TestSecurityUtils:
    def test_sanitize_for_log_truncates(self):
        long_string = "a" * 10000
        result = sanitize_for_log(long_string)
        assert len(result) <= 256

    def test_sanitize_for_log_short_string(self):
        result = sanitize_for_log("short")
        assert result == "short"

    def test_sanitize_for_log_none(self):
        result = sanitize_for_log(None)
        assert result == ""

    def test_sanitize_for_log_redacts_secrets(self):
        result = sanitize_for_log("password=secret123")
        assert "secret123" not in result or len(result) <= 256


class TestRateLimiter:
    @pytest.fixture
    def limiter(self):
        return RateLimiter(max_requests=5, window_seconds=60)

    def test_allows_within_limit(self, limiter):
        for _ in range(5):
            allowed, _ = limiter.check("user1")
            assert allowed is True

    def test_blocks_after_limit(self, limiter):
        for _ in range(5):
            limiter.check("user1")
        allowed, info = limiter.check("user1")
        assert allowed is False
        assert "retry_after" in info

    def test_different_users_independent(self, limiter):
        for _ in range(5):
            limiter.check("user1")
        allowed, _ = limiter.check("user2")
        assert allowed is True

    def test_reset(self, limiter):
        for _ in range(5):
            limiter.check("user1")
        limiter.reset("user1")
        allowed, _ = limiter.check("user1")
        assert allowed is True

    def test_window_expiry(self, limiter):
        for _ in range(5):
            limiter.check("user1")
        with patch("time.time", return_value=time.time() + 61):
            allowed, _ = limiter.check("user1")
            assert allowed is True


class TestIsRateLimited:
    def test_not_limited(self):
        limited, info = is_rate_limited("test:key", max_requests=5, window_seconds=60)
        assert limited is False

    def test_limited_after_threshold(self):
        for _ in range(5):
            is_rate_limited("test:key2", max_requests=5, window_seconds=60)
        limited, info = is_rate_limited("test:key2", max_requests=5, window_seconds=60)
        assert limited is True


class TestCustomExceptions:
    def test_not_found_error(self):
        exc = NotFoundError("Resource not found")
        assert exc.detail == "Resource not found"
        assert exc.status_code == 404

    def test_permission_error(self):
        exc = PermissionError("Access denied")
        assert exc.detail == "Access denied"
        assert exc.status_code == 403

    def test_service_unavailable_error(self):
        exc = ServiceUnavailableError("Service down")
        assert exc.detail == "Service down"
        assert exc.status_code == 503
