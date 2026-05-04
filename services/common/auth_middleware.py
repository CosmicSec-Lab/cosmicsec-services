"""Centralized authentication and authorization middleware for all CosmicSec services."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from typing import Any

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from jose import JWTError, jwt

logger = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET_KEY environment variable is required for auth middleware."
    )
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)

# ── Token Validation ───────────────────────────────────────────

def decode_access_token(token: str) -> dict[str, Any] | None:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        return None

# ── Authentication Dependencies ────────────────────────────────

async def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    api_key: str | None = Security(API_KEY_HEADER),
) -> dict[str, Any]:
    """
    Authenticate requests via Bearer token or X-API-Key header.

    Returns the user claims dict on success.
    Raises 401 if neither credential is valid.
    """
    # Try JWT Bearer token first
    if token:
        payload = decode_access_token(token)
        if payload:
            return {
                "id": payload.get("user_id"),
                "email": payload.get("sub"),
                "role": payload.get("role", "user"),
                "auth_method": "jwt",
            }

    # Try API key
    if api_key:
        # In production, validate against the auth service or database
        # For now, check format and let downstream services validate
        if api_key.startswith("csk_"):
            return {
                "id": None,
                "email": None,
                "role": "api_key",
                "auth_method": "api_key",
                "api_key_prefix": api_key[:8],
            }

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide a valid Bearer token or X-API-Key header.",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_active_user(
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """Ensure the authenticated user is active."""
    if not current_user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )
    return current_user


# ── Authorization Dependencies ─────────────────────────────────

def require_role(required_role: str) -> Callable:
    """Dependency factory: require a minimum role level."""
    role_hierarchy = {"viewer": 0, "user": 1, "analyst": 2, "admin": 3, "owner": 4}

    async def _check_role(
        current_user: dict[str, Any] = Depends(get_current_active_user),
    ) -> dict[str, Any]:
        user_role = current_user.get("role", "user")
        user_level = role_hierarchy.get(user_role, 0)
        required_level = role_hierarchy.get(required_role, 0)

        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role}' or higher required. Current role: '{user_role}'.",
            )
        return current_user

    return _check_role


def require_permission(permission: str) -> Callable:
    """Dependency factory: require a specific permission."""
    async def _check_permission(
        current_user: dict[str, Any] = Depends(get_current_active_user),
    ) -> dict[str, Any]:
        user_role = current_user.get("role", "user")

        # Role-to-permission mapping
        role_permissions = {
            "owner": {"read", "write", "delete", "manage", "admin"},
            "admin": {"read", "write", "delete", "manage"},
            "analyst": {"read", "write"},
            "user": {"read"},
            "viewer": {"read"},
        }

        allowed = role_permissions.get(user_role, set())
        if permission not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission}' required. Current role: '{user_role}'.",
            )
        return current_user

    return _check_permission


# ── Health Endpoint (No Auth Required) ─────────────────────────

HEALTH_PATHS = {"/health", "/metrics", "/docs", "/openapi.json", "/redoc"}


async def skip_auth_for_health(request: Request) -> bool:
    """Check if the request path should skip authentication."""
    return request.url.path in HEALTH_PATHS
