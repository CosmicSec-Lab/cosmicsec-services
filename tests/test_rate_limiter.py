"""Tests for the rate limiter module."""

import time
from unittest.mock import patch, MagicMock

import pytest

from services.common.rate_limiter import is_rate_limited, reset_limit, _memory_limits


class TestRateLimiterMemory:
    def setup_method(self):
        _memory_limits.clear()

    def teardown_method(self):
        _memory_limits.clear()

    def test_allows_first_request(self):
        limited, info = is_rate_limited("test:user", max_requests=3, window_seconds=60)
        assert limited is False
        assert info["remaining"] == 2

    def test_allows_up_to_limit(self):
        key = "test:limit"
        for i in range(3):
            limited, info = is_rate_limited(key, max_requests=3, window_seconds=60)
            assert limited is False, f"Request {i+1} should be allowed"

    def test_blocks_after_limit(self):
        key = "test:block"
        for _ in range(3):
            is_rate_limited(key, max_requests=3, window_seconds=60)
        limited, info = is_rate_limited(key, max_requests=3, window_seconds=60)
        assert limited is True
        assert info["remaining"] == 0
        assert info["retry_after"] > 0

    def test_retry_after_decreases(self):
        key = "test:decrease"
        max_req = 2
        for _ in range(max_req):
            is_rate_limited(key, max_requests=max_req, window_seconds=10)

        first_limited, first_info = is_rate_limited(key, max_requests=max_req, window_seconds=10)
        assert first_limited is True
        assert first_info["retry_after"] <= 10

        with patch("time.time", return_value=time.time() + 3):
            second_limited, second_info = is_rate_limited(key, max_requests=max_req, window_seconds=10)
            assert second_limited is True
            assert second_info["retry_after"] < first_info["retry_after"]

    def test_sliding_window_allows_after_expiry(self):
        key = "test:sliding"
        for _ in range(2):
            is_rate_limited(key, max_requests=2, window_seconds=5)

        limited, _ = is_rate_limited(key, max_requests=2, window_seconds=5)
        assert limited is True

        with patch("time.time", return_value=time.time() + 6):
            limited, _ = is_rate_limited(key, max_requests=2, window_seconds=5)
            assert limited is False

    def test_reset_clears_limit(self):
        key = "test:reset"
        for _ in range(2):
            is_rate_limited(key, max_requests=2, window_seconds=60)
        reset_limit(key)
        limited, info = is_rate_limited(key, max_requests=2, window_seconds=60)
        assert limited is False
        assert info["remaining"] == 1

    def test_different_keys_independent(self):
        for _ in range(2):
            is_rate_limited("test:user1", max_requests=2, window_seconds=60)
        limited, _ = is_rate_limited("test:user2", max_requests=2, window_seconds=60)
        assert limited is False

    def test_info_structure(self):
        _, info = is_rate_limited("test:info", max_requests=5, window_seconds=60)
        assert "limit" in info
        assert "remaining" in info
        assert "retry_after" in info
        assert isinstance(info["limit"], int)
        assert isinstance(info["remaining"], int)
        assert isinstance(info["retry_after"], int)
