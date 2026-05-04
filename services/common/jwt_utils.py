"""Shared JWT validation helper for WebSocket authentication."""

from __future__ import annotations

import logging
import os
import secrets

from jose import JWTError, jwt

logger = logging.getLogger(__name__)

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    raise RuntimeError(
        "JWT_SECRET_KEY environment variable is required. "
        "Generate one with: python -c 'import secrets; print(secrets.token_urlsafe(48))'"
    )
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")


def decode_token(token: str) -> dict | None:
    """Decode and validate a JWT token.

    Returns the decoded claims dict on success, or ``None`` if the token is
    invalid, expired, or malformed.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except JWTError:
        logger.debug("JWT validation failed", exc_info=True)
        return None
    except Exception:
        logger.debug("Unexpected error decoding JWT", exc_info=True)
        return None
