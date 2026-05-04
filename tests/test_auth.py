"""Tests for the authentication service endpoints."""

import os
from unittest.mock import MagicMock, patch

import pytest
from httpx import AsyncClient, ASGITransport

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-ci-only-not-for-production")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

from services.common.db import get_db
from services.auth_service.main import app


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
        assert data["service"] == "auth"
        assert "timestamp" in data


@pytest.mark.asyncio
async def test_metrics_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/metrics")
        assert response.status_code == 200
        assert "cosmicsec_auth_service_up" in response.text
        assert response.headers["content-type"].startswith("text/plain")


@pytest.mark.asyncio
async def test_register_success():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/register",
            json={
                "email": "newuser@example.com",
                "password": "SecurePass123!",
                "full_name": "New User",
                "role": "user",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert "user_id" in data
        assert data["email"] == "newuser@example.com"


@pytest.mark.asyncio
async def test_register_duplicate():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/register",
            json={
                "email": "dup@example.com",
                "password": "SecurePass123!",
                "full_name": "Dup User",
            },
        )
        response = await client.post(
            "/register",
            json={
                "email": "dup@example.com",
                "password": "SecurePass456!",
                "full_name": "Dup User 2",
            },
        )
        assert response.status_code == 400


@pytest.mark.asyncio
async def test_register_weak_password():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/register",
            json={
                "email": "weak@example.com",
                "password": "short",
                "full_name": "Weak User",
            },
        )
        assert response.status_code == 422


@pytest.mark.asyncio
async def test_register_invalid_email():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/register",
            json={
                "email": "not-an-email",
                "password": "SecurePass123!",
                "full_name": "Invalid Email",
            },
        )
        assert response.status_code == 422


@pytest.mark.asyncio
async def test_login_success():
    email = "login-test@example.com"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/register",
            json={
                "email": email,
                "password": "SecurePass123!",
                "full_name": "Login Test",
            },
        )
        response = await client.post(
            "/login",
            json={"email": email, "password": "SecurePass123!"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert "session_id" in data
        assert "user" in data


@pytest.mark.asyncio
async def test_login_wrong_password():
    email = "wrong-pass@example.com"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/register",
            json={
                "email": email,
                "password": "SecurePass123!",
                "full_name": "Wrong Pass",
            },
        )
        response = await client.post(
            "/login",
            json={"email": email, "password": "WrongPassword123!"},
        )
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_user():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/login",
            json={"email": "noone@example.com", "password": "SecurePass123!"},
        )
        assert response.status_code == 401


@pytest.mark.asyncio
async def test_verify_token_endpoint():
    email = "verify-test@example.com"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/register",
            json={
                "email": email,
                "password": "SecurePass123!",
                "full_name": "Verify Test",
            },
        )
        login_resp = await client.post(
            "/login",
            json={"email": email, "password": "SecurePass123!"},
        )
        token = login_resp.json()["access_token"]

        response = await client.get("/verify", params={"token": token})
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["email"] == email


@pytest.mark.asyncio
async def test_verify_invalid_token():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/verify", params={"token": "invalid.token.here"})
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is False


@pytest.mark.asyncio
async def test_forgot_password():
    email = "forgot@example.com"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post(
            "/register",
            json={
                "email": email,
                "password": "SecurePass123!",
                "full_name": "Forgot Test",
            },
        )
        response = await client.post("/forgot-password", json={"email": email})
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert data["sent"] is True


@pytest.mark.asyncio
async def test_forgot_password_nonexistent_user():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/forgot-password", json={"email": "noone@example.com"})
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert data["sent"] is True
