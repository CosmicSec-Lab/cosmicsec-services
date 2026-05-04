"""CORS configuration for all CosmicSec services.

Centralized CORS settings with secure defaults and environment-based overrides.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

_DEFAULT_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:8080",
]

_ENV_ORIGINS = os.getenv("CORS_ALLOWED_ORIGINS", "")


def _get_allowed_origins() -> list[str]:
    if _ENV_ORIGINS:
        return [o.strip() for o in _ENV_ORIGINS.split(",") if o.strip()]
    if os.getenv("DEPLOYMENT_ENV") == "production":
        return []
    return _DEFAULT_ORIGINS


def setup_cors(
    app: FastAPI,
    *,
    allow_origins: list[str] | None = None,
    allow_credentials: bool = True,
    allow_methods: list[str] | None = None,
    allow_headers: list[str] | None = None,
    max_age: int = 600,
) -> None:
    origins = allow_origins or _get_allowed_origins()
    methods = allow_methods or ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    headers = allow_headers or [
        "Authorization",
        "Content-Type",
        "X-Request-ID",
        "X-Trace-ID",
        "Accept",
        "Origin",
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=allow_credentials,
        allow_methods=methods,
        allow_headers=headers,
        max_age=max_age,
    )
