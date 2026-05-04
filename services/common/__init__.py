"""CosmicSec shared service utilities."""

from services.common.db import Base, SessionLocal, get_db
from services.common.exceptions import (
    CosmicSecException,
    ValidationError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    ConflictError,
    RateLimitError,
    ServiceUnavailableError,
    ExternalServiceError,
    register_exception_handlers,
)
from services.common.security_utils import (
    sanitize_for_log,
    normalize_org_slug,
    sanitize_scan_id,
    validate_outbound_url,
    ensure_safe_child_path,
)
from services.common.rate_limiter import is_rate_limited, reset_limit
from services.common.cors import setup_cors
from services.common.request_id import RequestIDMiddleware, get_request_id
from services.common.pagination import Page, compute_offset
from services.common.observability import setup_observability
from services.common.token_blacklist import blacklist_token, is_token_blacklisted
from services.common.jwt_utils import decode_jwt, create_jwt

__all__ = [
    "Base",
    "SessionLocal",
    "get_db",
    "CosmicSecException",
    "ValidationError",
    "AuthenticationError",
    "AuthorizationError",
    "NotFoundError",
    "ConflictError",
    "RateLimitError",
    "ServiceUnavailableError",
    "ExternalServiceError",
    "register_exception_handlers",
    "sanitize_for_log",
    "normalize_org_slug",
    "sanitize_scan_id",
    "validate_outbound_url",
    "ensure_safe_child_path",
    "is_rate_limited",
    "reset_limit",
    "setup_cors",
    "RequestIDMiddleware",
    "get_request_id",
    "Page",
    "compute_offset",
    "setup_observability",
    "blacklist_token",
    "is_token_blacklisted",
    "decode_jwt",
    "create_jwt",
]
