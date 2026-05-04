"""Tests for security utilities."""

from pathlib import Path
import tempfile

import pytest

from services.common.security_utils import (
    sanitize_for_log,
    normalize_org_slug,
    sanitize_scan_id,
    validate_outbound_url,
    ensure_safe_child_path,
)


class TestSanitizeForLog:
    def test_short_string_unchanged(self):
        assert sanitize_for_log("hello") == "hello"

    def test_truncates_long_string(self):
        result = sanitize_for_log("a" * 500)
        assert len(result) == 256
        assert result.endswith("...")

    def test_removes_control_chars(self):
        result = sanitize_for_log("hello\nworld\ttest")
        assert "\n" not in result
        assert "\t" not in result

    def test_handles_none(self):
        result = sanitize_for_log(None)
        assert result == "None"

    def test_handles_numbers(self):
        assert sanitize_for_log(42) == "42"

    def test_custom_max_length(self):
        result = sanitize_for_log("1234567890", max_length=8)
        assert len(result) == 8


class TestNormalizeOrgSlug:
    def test_valid_slug(self):
        assert normalize_org_slug("my-org") == "my-org"

    def test_lowercase_conversion(self):
        assert normalize_org_slug("MY-ORG") == "my-org"

    def test_trims_whitespace(self):
        assert normalize_org_slug("  my-org  ") == "my-org"

    def test_invalid_chars_returns_default(self):
        assert normalize_org_slug("my org!") == "default"

    def test_starts_with_invalid_char(self):
        assert normalize_org_slug("-my-org") == "default"

    def test_empty_returns_default(self):
        assert normalize_org_slug("") == "default"

    def test_custom_default(self):
        assert normalize_org_slug("", default="fallback") == "fallback"

    def test_too_long(self):
        assert normalize_org_slug("a" * 100) == "default"


class TestSanitizeScanId:
    def test_valid_id(self):
        assert sanitize_scan_id("scan-123") == "scan-123"

    def test_removes_special_chars(self):
        assert sanitize_scan_id("scan/123") == "scan_123"

    def test_trims_dots_dashes(self):
        assert sanitize_scan_id("...scan-123...") == "scan-123"

    def test_empty_returns_report(self):
        assert sanitize_scan_id("") == "report"

    def test_truncates_long(self):
        result = sanitize_scan_id("a" * 200)
        assert len(result) <= 80


class TestValidateOutboundUrl:
    def test_valid_https(self):
        url = validate_outbound_url("https://example.com/api")
        assert url == "https://example.com/api"

    def test_rejects_private_by_default(self):
        url = validate_outbound_url("http://localhost:8080")
        assert url is None

    def test_rejects_file_scheme(self):
        url = validate_outbound_url("file:///etc/passwd")
        assert url is None

    def test_allow_private_hosts(self):
        url = validate_outbound_url("http://192.168.1.1", allow_private_hosts=True)
        assert url is not None

    def test_allowed_hosts_whitelist(self):
        url = validate_outbound_url(
            "https://api.example.com", allowed_hosts={"api.example.com"}
        )
        assert url is not None

    def test_rejects_non_whitelisted(self):
        url = validate_outbound_url(
            "https://other.com", allowed_hosts={"api.example.com"}
        )
        assert url is None

    def test_require_https(self):
        url = validate_outbound_url("http://example.com", require_https=True)
        assert url is None

    def test_empty_url(self):
        assert validate_outbound_url("") is None

    def test_onion_rejected_by_default(self):
        url = validate_outbound_url("http://abc123.onion")
        assert url is None

    def test_onion_allowed(self):
        url = validate_outbound_url("http://abc123.onion", allow_onion_hosts=True)
        assert url is not None


class TestEnsureSafeChildPath:
    def test_valid_child(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            result = ensure_safe_child_path(base, "report.txt")
            assert result.name == "report.txt"
            assert str(result).startswith(str(base.resolve()))

    def test_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            with pytest.raises(ValueError, match="Unsafe path"):
                ensure_safe_child_path(base, "../etc/passwd")

    def test_rejects_absolute_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            with pytest.raises(ValueError, match="Unsafe path"):
                ensure_safe_child_path(base, "/etc/passwd")
