"""Tests for the scan service endpoints."""

import os
from unittest.mock import MagicMock, patch

import pytest
from httpx import AsyncClient, ASGITransport

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from services.common.db import get_db
from services.scan_service.main import app


@pytest.fixture
def override_db():
    def _get_test_db():
        try:
            yield MagicMock()
        finally:
            pass

    app.dependency_overrides[get_db] = _get_test_db
    yield
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_health_check():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "scan"


@pytest.mark.asyncio
async def test_metrics_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/metrics")
        assert response.status_code == 200
        assert "cosmicsec_scan_service_up" in response.text


@pytest.mark.asyncio
async def test_create_scan_requires_auth():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/scans",
            json={"target": "example.com", "scan_types": ["nmap"]},
        )
        assert response.status_code in (401, 403, 422)
