"""
CosmicSec Request Validation and Enhancement Middleware

Provides middleware for:
- Request validation and sanitization
- Request/Response logging with sensitive data masking
- Request ID and Trace ID propagation
- Performance monitoring
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import Callable
from typing import Any

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# Sensitive fields to mask in logs
SENSITIVE_FIELDS = {
    "password",
    "token",
    "authorization",
    "api_key",
    "secret",
    "credential",
    "access_token",
    "refresh_token",
    "private_key",
}


def mask_sensitive_data(data: Any, depth: int = 0, max_depth: int = 5) -> Any:
    """Recursively mask sensitive data in dictionaries and lists."""
    if depth > max_depth:
        return data

    if isinstance(data, dict):
        return {
            k: "***REDACTED***"
            if any(sensitive in k.lower() for sensitive in SENSITIVE_FIELDS)
            else mask_sensitive_data(v, depth + 1, max_depth)
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [mask_sensitive_data(item, depth + 1, max_depth) for item in data]
    return data


class RequestEnhancementMiddleware(BaseHTTPMiddleware):
    """Enhances requests with request ID and trace ID."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate or get request ID
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        trace_id = request.headers.get("X-Trace-ID") or str(uuid.uuid4())

        # Add to request scope for later use
        request.scope["request_id"] = request_id
        request.scope["trace_id"] = trace_id

        # Get response
        response = await call_next(request)

        # Add trace headers to response
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Trace-ID"] = trace_id

        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logs requests and responses with performance metrics."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID", "unknown")
        start_time = time.time()

        # Log request metadata only — avoid consuming the body stream
        # so downstream handlers can still read it.
        content_type = request.headers.get("content-type", "")
        content_length = int(request.headers.get("content-length", 0))

        logger.info(
            f"{request.method} {request.url.path}",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "query": dict(request.query_params),
                "body_size": content_length,
                "content_type": content_type,
                "client": request.client.host if request.client else None,
            },
        )

        # Get response
        response = await call_next(request)

        # Calculate response time
        response_time_ms = (time.time() - start_time) * 1000

        # Log response
        logger.info(
            f"{response.status_code} {request.method} {request.url.path}",
            extra={
                "request_id": request_id,
                "status_code": response.status_code,
                "response_time_ms": round(response_time_ms, 2),
                "method": request.method,
                "path": request.url.path,
            },
        )

        response.headers["X-Response-Time-Ms"] = str(round(response_time_ms, 2))

        return response


class InputValidationMiddleware(BaseHTTPMiddleware):
    """Validates common input patterns and prevents common attacks."""

    # Maximum request body size (10 MB)
    MAX_BODY_SIZE = 10 * 1024 * 1024

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Check Content-Length
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.MAX_BODY_SIZE:
            logger.warning(
                f"Request body too large: {content_length} bytes",
                extra={
                    "path": request.url.path,
                    "content_length": content_length,
                },
            )
            return Response(
                content="Request body too large",
                status_code=413,
            )

        # Check for suspicious patterns in path
        suspicious_patterns = ["../", "//", "%2e%2e", "..\\"]
        if any(pattern in request.url.path for pattern in suspicious_patterns):
            logger.warning(
                f"Suspicious path pattern detected: {request.url.path}",
                extra={"path": request.url.path},
            )
            return Response(
                content="Invalid request path",
                status_code=400,
            )

        return await call_next(request)
