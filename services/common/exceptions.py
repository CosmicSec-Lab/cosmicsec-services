"""CosmicSec Unified Error Handling System.

Merged from error_handling.py and exceptions.py — provides standardized error
responses, custom exceptions, rate-limit awareness, and FastAPI handler registration.
"""

from __future__ import annotations

import logging
import traceback
from datetime import UTC, datetime
from enum import Enum, StrEnum
from typing import Any, Generic, TypeVar

from fastapi import Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ── Error Codes ─────────────────────────────────────────────────

class ErrorCode(StrEnum):
    AUTH_INVALID_CREDENTIALS = "AUTH_INVALID_CREDENTIALS"
    AUTH_MISSING_TOKEN = "AUTH_MISSING_TOKEN"
    AUTH_EXPIRED_TOKEN = "AUTH_EXPIRED_TOKEN"
    AUTH_INVALID_TOKEN = "AUTH_INVALID_TOKEN"
    AUTH_INSUFFICIENT_PERMISSIONS = "AUTH_INSUFFICIENT_PERMISSIONS"
    AUTH_ACCOUNT_DISABLED = "AUTH_ACCOUNT_DISABLED"
    AUTH_MFA_REQUIRED = "AUTH_MFA_REQUIRED"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    RESOURCE_ALREADY_EXISTS = "RESOURCE_ALREADY_EXISTS"
    RESOURCE_CONFLICT = "RESOURCE_CONFLICT"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INVALID_INPUT = "INVALID_INPUT"
    MISSING_PARAMETER = "MISSING_PARAMETER"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    SERVICE_TIMEOUT = "SERVICE_TIMEOUT"
    SERVICE_DEGRADED = "SERVICE_DEGRADED"
    EXTERNAL_SERVICE_ERROR = "EXTERNAL_SERVICE_ERROR"
    EXTERNAL_SERVICE_TIMEOUT = "EXTERNAL_SERVICE_TIMEOUT"
    DATABASE_ERROR = "DATABASE_ERROR"
    DATABASE_CONSTRAINT_VIOLATION = "DATABASE_CONSTRAINT_VIOLATION"
    INVALID_STATE = "INVALID_STATE"
    OPERATION_NOT_ALLOWED = "OPERATION_NOT_ALLOWED"
    DEPENDENCY_NOT_SATISFIED = "DEPENDENCY_NOT_SATISFIED"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    MISSING_CONFIGURATION = "MISSING_CONFIGURATION"
    SCAN_FAILED = "SCAN_FAILED"
    SCAN_TIMEOUT = "SCAN_TIMEOUT"
    TOOL_NOT_AVAILABLE = "TOOL_NOT_AVAILABLE"
    INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"


class ErrorSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    WARNING = "warning"
    HIGH = "high"
    ERROR = "error"
    CRITICAL = "critical"


# ── Response Models ─────────────────────────────────────────────

class ErrorResponse(BaseModel):
    """Standardized error response model."""
    error: str
    code: ErrorCode = Field(default=ErrorCode.INTERNAL_SERVER_ERROR)
    severity: ErrorSeverity = Field(default=ErrorSeverity.MEDIUM)
    request_id: str | None = None
    trace_id: str | None = None
    timestamp: str | None = None
    details: dict[str, Any] | None = None
    suggestion: str | None = None


class SuccessResponse(BaseModel, Generic[T]):
    """Standardized success response model."""
    success: bool = True
    data: T | None = None
    message: str | None = None
    timestamp: str | None = None
    request_id: str | None = None


# ── Base Exception ──────────────────────────────────────────────

class CosmicSecException(Exception):
    """Base exception for all CosmicSec errors."""

    def __init__(
        self,
        message: str,
        error_code: ErrorCode = ErrorCode.INTERNAL_SERVER_ERROR,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        severity: ErrorSeverity = ErrorSeverity.ERROR,
        details: dict[str, Any] | None = None,
        suggestion: str | None = None,
    ):
        self.message = message
        self.error_code = error_code
        self.code = error_code  # alias for error_handling compat
        self.status_code = status_code
        self.severity = severity
        self.details = details or {}
        self.suggestion = suggestion
        self.timestamp = datetime.now(tz=UTC).isoformat()
        super().__init__(message)

    def to_dict(self) -> dict[str, Any]:
        response = {
            "detail": self.message,
            "error_code": self.error_code.value,
            "timestamp": self.timestamp,
        }
        if self.details:
            response["details"] = self.details
        if self.suggestion:
            response["suggestion"] = self.suggestion
        return response


# ── Specialized Exceptions ──────────────────────────────────────

class ValidationError(CosmicSecException):
    def __init__(self, message: str, fields: dict[str, str] | None = None, **kwargs):
        details = {"validation_errors": fields or {}}
        super().__init__(
            message, ErrorCode.VALIDATION_ERROR,
            status.HTTP_422_UNPROCESSABLE_ENTITY, ErrorSeverity.LOW,
            details=details, **kwargs,
        )


class AuthenticationError(CosmicSecException):
    def __init__(self, message: str = "Authentication failed",
                 error_code: ErrorCode = ErrorCode.AUTH_INVALID_CREDENTIALS):
        super().__init__(
            message, error_code,
            status.HTTP_401_UNAUTHORIZED, ErrorSeverity.WARNING,
        )


class AuthorizationError(CosmicSecException):
    def __init__(self, message: str = "Insufficient permissions",
                 required_role: str | None = None):
        super().__init__(
            message, ErrorCode.AUTH_INSUFFICIENT_PERMISSIONS,
            status.HTTP_403_FORBIDDEN, ErrorSeverity.WARNING,
            details={"required_role": required_role},
        )


class NotFoundError(CosmicSecException):
    def __init__(self, resource_type: str, resource_id: Any):
        super().__init__(
            f"{resource_type} with ID '{resource_id}' not found",
            ErrorCode.RESOURCE_NOT_FOUND,
            status.HTTP_404_NOT_FOUND, ErrorSeverity.INFO,
            details={"resource_type": resource_type, "resource_id": str(resource_id)},
        )


class ConflictError(CosmicSecException):
    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(
            message, ErrorCode.RESOURCE_CONFLICT,
            status.HTTP_409_CONFLICT, ErrorSeverity.WARNING,
            details=details,
        )


class RateLimitError(CosmicSecException):
    def __init__(self, message: str = "Rate limit exceeded",
                 retry_after: int | None = None, **kwargs):
        details = {}
        if retry_after:
            details["retry_after_seconds"] = retry_after
        super().__init__(
            message, ErrorCode.RATE_LIMIT_EXCEEDED,
            status.HTTP_429_TOO_MANY_REQUESTS, ErrorSeverity.INFO,
            details=details, **kwargs,
        )


class ServiceUnavailableError(CosmicSecException):
    def __init__(self, service_name: str, message: str | None = None,
                retry_after: int | None = None):
        msg = message or f"Service '{service_name}' is temporarily unavailable"
        details = {"service": service_name}
        if retry_after:
            details["retry_after_seconds"] = retry_after
        super().__init__(
            msg, ErrorCode.SERVICE_UNAVAILABLE,
            status.HTTP_503_SERVICE_UNAVAILABLE, ErrorSeverity.ERROR,
            details=details,
            suggestion="Please try again in a few moments",
        )


class ExternalServiceError(CosmicSecException):
    def __init__(self, service_name: str, original_error: str | None = None, **kwargs):
        super().__init__(
            f"External service '{service_name}' returned an error",
            ErrorCode.EXTERNAL_SERVICE_ERROR,
            status.HTTP_502_BAD_GATEWAY, ErrorSeverity.ERROR,
            details={"external_service": service_name, "original_error": original_error},
            suggestion="The issue is with an external service. Please try again later.",
            **kwargs,
        )


class ResourceNotFoundException(CosmicSecException):
    def __init__(self, resource: str = "Resource", identifier: str | int | None = None,
                suggestion: str | None = None):
        message = f"{resource} not found"
        if identifier:
            message += f" (ID: {identifier})"
        super().__init__(
            message, ErrorCode.RESOURCE_NOT_FOUND,
            status.HTTP_404_NOT_FOUND, ErrorSeverity.INFO,
            suggestion=suggestion,
        )


# ── FastAPI Exception Handlers ──────────────────────────────────

async def cosmic_sec_exception_handler(
    request: Request, exc: CosmicSecException
) -> JSONResponse:
    logger.error(
        "CosmicSec exception: %s — %s",
        exc.error_code, exc.message,
        extra={"code": exc.error_code.value, "severity": exc.severity.value, "details": exc.details},
    )
    error_response = ErrorResponse(
        error=exc.message,
        code=exc.error_code,
        severity=exc.severity,
        request_id=request.headers.get("X-Request-ID"),
        trace_id=request.headers.get("X-Trace-ID"),
        details=exc.details if exc.details else None,
        suggestion=exc.suggestion,
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=jsonable_encoder(error_response),
    )


async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception(
        "Unhandled exception",
        extra={
            "path": request.url.path,
            "method": request.method,
            "client": request.client.host if request.client else None,
            "traceback": traceback.format_exc(),
        },
    )
    error_response = ErrorResponse(
        error="An unexpected error occurred",
        code=ErrorCode.INTERNAL_SERVER_ERROR,
        severity=ErrorSeverity.HIGH,
        request_id=request.headers.get("X-Request-ID"),
        trace_id=request.headers.get("X-Trace-ID"),
        suggestion="Please try again later or contact support if the issue persists",
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=jsonable_encoder(error_response),
    )


def register_exception_handlers(app: Any) -> None:
    """Register all exception handlers with a FastAPI app."""
    app.add_exception_handler(CosmicSecException, cosmic_sec_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)


def log_exception(
    exception: Exception,
    context: dict[str, Any] | None = None,
    level: int = logging.ERROR,
) -> None:
    """Log exception with context."""
    error_info = {
        "exception_type": type(exception).__name__,
        "exception_message": str(exception),
    }
    if context:
        error_info.update(context)
    if isinstance(exception, CosmicSecException):
        error_info.update({
            "error_code": exception.error_code.value,
            "status_code": exception.status_code,
            "severity": exception.severity.value,
        })
    logger.log(level, "Exception occurred: %s", error_info, exc_info=True)
