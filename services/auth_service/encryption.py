"""Fernet-based encryption for 2FA secrets at rest."""

import logging
import os

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    """Return a cached Fernet instance, creating one on first call."""
    global _fernet  # noqa: PLW0603
    if _fernet is not None:
        return _fernet

    key = os.getenv("COSMICSEC_2FA_KEY")
    if not key:
        key = Fernet.generate_key().decode()
        logger.warning(
            "COSMICSEC_2FA_KEY is not set — auto-generated an ephemeral key. "
            "2FA secrets will NOT survive a restart. "
            "Set COSMICSEC_2FA_KEY to a valid Fernet key in production."
        )
    _fernet = Fernet(key.encode() if isinstance(key, str) else key)
    return _fernet


def encrypt_2fa_secret(secret: str) -> str:
    """Encrypt a TOTP secret and return a URL-safe base64 token."""
    try:
        return _get_fernet().encrypt(secret.encode("utf-8")).decode("utf-8")
    except Exception:
        logger.exception("Failed to encrypt 2FA secret")
        raise


def decrypt_2fa_secret(encrypted: str) -> str:
    """Decrypt a previously encrypted TOTP secret."""
    try:
        return _get_fernet().decrypt(encrypted.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        logger.error("Failed to decrypt 2FA secret — invalid token or wrong key")
        raise
    except Exception:
        logger.exception("Unexpected error decrypting 2FA secret")
        raise
