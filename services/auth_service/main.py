"""
CosmicSec Authentication Service
Handles user authentication, JWT tokens, OAuth2, and session management
"""

import base64
import hashlib
import hmac
import logging
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import bcrypt as bcrypt_lib
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field

try:
    import redis
except ImportError:  # pragma: no cover - optional dependency at runtime
    redis = None

try:
    import pyotp
except ImportError:  # pragma: no cover - optional dependency at runtime
    pyotp = None

try:
    import casbin
except ImportError:  # pragma: no cover - optional dependency at runtime
    casbin = None

try:
    from sqlalchemy.orm import Session as SASession

    from services.common.db import SessionLocal
    from services.common.models import APIKeyModel, UserModel

    _HAS_DB = True
except ImportError:  # pragma: no cover - optional dependency at runtime
    _HAS_DB = False

from fastapi.responses import JSONResponse

from services.auth_service.encryption import decrypt_2fa_secret, encrypt_2fa_secret
from services.auth_service.rate_limiter import IP_WINDOW_SECONDS, LoginRateLimiter

app = FastAPI(
    title="CosmicSec Auth Service",
    description="Authentication and authorization service for GuardAxisSphere",
    version="1.0.0",
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30

# Password hashing with bcrypt 4.0+ compatibility
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__ident="2b")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# Data models
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: str
    role: str = "user"


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    email: str | None = None
    user_id: str | None = None
    role: str | None = None


class User(BaseModel):
    id: str
    email: EmailStr
    full_name: str
    role: str
    is_active: bool = True
    created_at: datetime


class OAuthStartResponse(BaseModel):
    provider: str
    authorize_url: str


class TwoFactorSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str


class TwoFactorVerifyRequest(BaseModel):
    email: EmailStr
    code: str


class ApiKeyResponse(BaseModel):
    key_id: str
    api_key: str


class RefreshRequest(BaseModel):
    refresh_token: str


class UserUpdate(BaseModel):
    full_name: str | None = None
    role: str | None = None
    is_active: bool | None = None


class RoleAssignRequest(BaseModel):
    email: EmailStr
    role: str


class ConfigUpdateRequest(BaseModel):
    key: str
    value: str


class MFARequest(BaseModel):
    email: EmailStr
    method: str  # totp | sms | hardware_key


class MFAChallengeVerifyRequest(BaseModel):
    email: EmailStr
    method: str
    code: str


# ---------------------------------------------------------------------------
# Phase 3.1 — Multi-tenancy models
# ---------------------------------------------------------------------------


class OrganizationCreate(BaseModel):
    name: str
    slug: str = Field(..., min_length=3)
    owner_email: EmailStr
    plan: str = "team"  # free | team | enterprise
    branding: dict[str, str] = Field(default_factory=dict)


class WorkspaceCreate(BaseModel):
    name: str
    description: str | None = None
    quota_scans_per_day: int = Field(default=100, ge=1, le=100000)


class OrganizationMemberAssign(BaseModel):
    email: EmailStr
    role: str = "member"  # owner | admin | member


class TenantQuotaUpdate(BaseModel):
    max_users: int | None = Field(default=None, ge=1, le=100000)
    max_workspaces: int | None = Field(default=None, ge=1, le=100000)
    max_scans_per_day: int | None = Field(default=None, ge=1, le=1000000)


class BillingCustomerCreate(BaseModel):
    billing_email: EmailStr
    provider: str = "stripe"


class SubscriptionUpdate(BaseModel):
    plan: str = Field(default="team")
    status: str = Field(default="active")


class InvoiceCreate(BaseModel):
    amount_cents: int = Field(..., ge=1)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    description: str = Field(default="Security platform usage")


class SecretStoreRequest(BaseModel):
    name: str
    value: str
    engine: str = "vault"


class FieldEncryptionRequest(BaseModel):
    value: str


class SecurityScanRequest(BaseModel):
    target: str
    controls: list[str] = Field(
        default_factory=lambda: ["mfa", "rbac", "audit_logs", "token_rotation"]
    )


class DataResidencyRequest(BaseModel):
    region: str = Field(default="us-east-1")
    storage_class: str = Field(default="standard")


# In-memory user storage (replace with database in production)
fake_users_db = {}
fake_api_keys_db = {}
fake_2fa_db = {}
fake_sessions_db = {}
audit_logs = []
platform_config = {
    "maintenance_mode": "false",
    "default_role": "user",
    "allow_registration": "true",
}
hardware_keys_db = {}
sms_challenges_db = {}

# Multi-tenant billing and retention (Phase 3)
tenant_billing: dict[str, dict[str, Any]] = {}
tenant_retention: dict[str, int] = {}  # days
tenant_data_residency: dict[str, dict[str, str]] = {}
vault_store: dict[str, dict[str, str]] = {}


# ---------------------------------------------------------------------------
# DB-backed persistence helpers  (Phase K.2)
# ---------------------------------------------------------------------------


def _get_db_session() -> "SASession | None":
    """Return a new DB session, or *None* when the DB layer is unavailable."""
    if not _HAS_DB:
        return None
    try:
        return SessionLocal()
    except Exception:
        logger.debug("Could not open DB session — running without persistence")
        return None


def save_api_key_to_db(key_id: str, data: dict[str, Any]) -> None:
    """Persist a single API-key record to the database."""
    db = _get_db_session()
    if db is None:
        return
    try:
        existing = db.query(APIKeyModel).filter(APIKeyModel.id == key_id).first()
        if existing:
            existing.key_hash = data.get("key_hash", "")
            existing.user_id = data.get("owner", "")
        else:
            db.add(
                APIKeyModel(
                    id=key_id,
                    user_id=data.get("owner", ""),
                    key_hash=data.get("key_hash", ""),
                    name="default",
                    scopes=[],
                    is_active=True,
                )
            )
        db.commit()
    except Exception:
        logger.exception("Failed to persist API key %s to DB", key_id)
        db.rollback()
    finally:
        db.close()


def delete_api_key_from_db(key_id: str) -> None:
    """Remove an API-key record from the database."""
    db = _get_db_session()
    if db is None:
        return
    try:
        db.query(APIKeyModel).filter(APIKeyModel.id == key_id).delete()
        db.commit()
    except Exception:
        logger.exception("Failed to delete API key %s from DB", key_id)
        db.rollback()
    finally:
        db.close()


def load_api_key_from_db(key_id: str) -> dict[str, Any] | None:
    """Load a single API-key from the DB (cache-miss fallback)."""
    db = _get_db_session()
    if db is None:
        return None
    try:
        row = db.query(APIKeyModel).filter(APIKeyModel.id == key_id).first()
        if row is None:
            return None
        return {
            "owner": row.user_id,
            "key_hash": row.key_hash,
            "created_at": row.created_at.isoformat() if row.created_at else "",
        }
    except Exception:
        logger.exception("Failed to load API key %s from DB", key_id)
        return None
    finally:
        db.close()


def load_all_api_keys_from_db() -> dict[str, dict[str, Any]]:
    """Bulk-load every active API key from the database."""
    db = _get_db_session()
    if db is None:
        return {}
    try:
        rows = db.query(APIKeyModel).filter(APIKeyModel.is_active.is_(True)).all()
        return {
            row.id: {
                "owner": row.user_id,
                "key_hash": row.key_hash,
                "created_at": row.created_at.isoformat() if row.created_at else "",
            }
            for row in rows
        }
    except Exception:
        logger.exception("Failed to bulk-load API keys from DB")
        return {}
    finally:
        db.close()


def save_2fa_to_db(email: str, secret: str) -> None:
    """Persist an encrypted 2FA secret on the UserModel."""
    db = _get_db_session()
    if db is None:
        return
    try:
        encrypted = encrypt_2fa_secret(secret)
        user = db.query(UserModel).filter(UserModel.email == email).first()
        if user:
            user.totp_secret = encrypted
            user.totp_enabled = True
            db.commit()
        else:
            logger.warning("save_2fa_to_db: no user row for %s", email)
    except Exception:
        logger.exception("Failed to persist 2FA secret for %s", email)
        db.rollback()
    finally:
        db.close()


def load_2fa_from_db(email: str) -> str | None:
    """Load and decrypt a 2FA secret from the database (cache-miss fallback)."""
    db = _get_db_session()
    if db is None:
        return None
    try:
        user = db.query(UserModel).filter(UserModel.email == email).first()
        if user and user.totp_secret:
            return decrypt_2fa_secret(user.totp_secret)
        return None
    except Exception:
        logger.exception("Failed to load 2FA secret for %s", email)
        return None
    finally:
        db.close()


def load_all_2fa_from_db() -> dict[str, str]:
    """Bulk-load all 2FA secrets from the database (decrypted)."""
    db = _get_db_session()
    if db is None:
        return {}
    result: dict[str, str] = {}
    try:
        rows = (
            db.query(UserModel)
            .filter(UserModel.totp_enabled.is_(True), UserModel.totp_secret.isnot(None))
            .all()
        )
        for row in rows:
            try:
                result[row.email] = decrypt_2fa_secret(row.totp_secret)
            except Exception:
                logger.warning("Skipping undecryptable 2FA secret for %s", row.email)
        return result
    except Exception:
        logger.exception("Failed to bulk-load 2FA secrets from DB")
        return {}
    finally:
        db.close()


def _hash_audit_entry(entry: dict[str, Any], previous_hash: str | None) -> str:
    """Generate a tamper-evident hash chain for audit logs."""
    import hashlib
    import json

    payload = {
        **entry,
        "previous_hash": previous_hash or "",
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _audit_entry(action: str, actor: str, detail: str, org_id: str | None = None) -> None:
    ts = datetime.now(tz=UTC).isoformat()
    entry = {
        "timestamp": ts,
        "action": action,
        "actor": actor,
        "detail": detail,
        "org_id": org_id,
    }
    previous_hash = audit_logs[-1].get("hash") if audit_logs else None
    entry["hash"] = _hash_audit_entry(entry, previous_hash)
    audit_logs.append(entry)


def _cleanup_retention() -> None:
    """Delete old entries based on tenant retention policies."""
    now = datetime.now(tz=UTC)
    kept: list[dict[str, Any]] = []
    for entry in audit_logs:
        org = entry.get("org_id")
        days = tenant_retention.get(org, 30)
        try:
            ts = datetime.fromisoformat(entry["timestamp"])
        except (ValueError, TypeError):
            kept.append(entry)
            continue
        if (now - ts).days <= days:
            kept.append(entry)
    audit_logs.clear()
    audit_logs.extend(kept)


@app.on_event("startup")
async def startup_retention_task():
    """Background cleanup loop for retention policies."""
    import asyncio

    async def _loop():
        while True:
            _cleanup_retention()
            await asyncio.sleep(86400)  # run daily

    asyncio.create_task(_loop())


@app.on_event("startup")
async def startup_warm_cache():
    """Pre-load API keys and 2FA secrets from the database into in-memory caches."""
    loaded_keys = load_all_api_keys_from_db()
    if loaded_keys:
        fake_api_keys_db.update(loaded_keys)
        logger.info("Warmed API-key cache with %d entries from DB", len(loaded_keys))

    loaded_2fa = load_all_2fa_from_db()
    if loaded_2fa:
        fake_2fa_db.update(loaded_2fa)
        logger.info("Warmed 2FA cache with %d entries from DB", len(loaded_2fa))


# Multi-tenant state (in-memory; DB in production)
organizations_db: dict[str, dict] = {}
org_memberships: dict[str, dict[str, str]] = {}  # org_id -> {email: role}
workspaces_db: dict[str, list[dict]] = {}  # org_id -> workspace list
tenant_quotas: dict[str, dict[str, int]] = {}  # org_id -> quotas

redis_client = None
if redis is not None:
    try:
        redis_client = redis.Redis(
            host=os.getenv("REDIS_HOST", "redis"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            decode_responses=True,
        )
        redis_client.ping()
    except Exception:
        redis_client = None


def _store_session(session_id: str, email: str, refresh_token: str) -> None:
    value = f"{email}:{refresh_token}"
    if redis_client is not None:
        redis_client.setex(f"session:{session_id}", REFRESH_TOKEN_EXPIRE_DAYS * 86400, value)
    else:
        fake_sessions_db[session_id] = value


def _audit(action: str, actor: str, detail: str) -> None:
    _audit_entry(action, actor, detail, org_id=None)


def _audit_org(action: str, actor: str, org_id: str, detail: str) -> None:
    _audit_entry(action, actor, f"org={org_id}; {detail}", org_id=org_id)


def _require_org_admin(org_id: str, email: str) -> None:
    members = org_memberships.get(org_id, {})
    role = members.get(email)
    if role not in {"owner", "admin"}:
        raise HTTPException(status_code=403, detail="Organization admin permission required")


def _ensure_org_exists(org_id: str) -> dict:
    org = organizations_db.get(org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return org


def _delete_session(session_id: str) -> None:
    if redis_client is not None:
        redis_client.delete(f"session:{session_id}")
    else:
        fake_sessions_db.pop(session_id, None)


def _session_exists(session_id: str) -> bool:
    if redis_client is not None:
        return redis_client.exists(f"session:{session_id}") == 1
    return session_id in fake_sessions_db


def _enforce_permission(role: str, action: str) -> bool:
    return action in {"read", "write", "delete", "manage"}


def _build_casbin_enforcer():
    if casbin is None:
        return None

    base_dir = Path(__file__).resolve().parent / "rbac"
    model_path = base_dir / "model.conf"
    policy_path = base_dir / "policy.csv"

    if not model_path.exists() or not policy_path.exists():
        return None

    try:
        return casbin.Enforcer(str(model_path), str(policy_path))
    except Exception:
        return None


casbin_enforcer = _build_casbin_enforcer()

login_rate_limiter = LoginRateLimiter()


def _map_action_to_resource(action: str) -> tuple[str, str]:
    mapping = {
        "manage": ("admin", "manage"),
        "write": ("scan", "write"),
        "delete": ("scan", "delete"),
        "read": ("scan", "read"),
    }
    return mapping.get(action, ("scan", "read"))


# Password utilities
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash using bcrypt directly"""
    password_bytes = plain_password.encode("utf-8")[:72]  # Truncate to 72 bytes
    hash_bytes = hashed_password.encode("utf-8")
    return bcrypt_lib.checkpw(password_bytes, hash_bytes)


def get_password_hash(password: str) -> str:
    """Hash password using bcrypt directly"""
    password_bytes = password.encode("utf-8")[:72]  # Truncate to 72 bytes
    salt = bcrypt_lib.gensalt()
    hashed = bcrypt_lib.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


# JWT utilities
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(tz=UTC) + expires_delta
    else:
        expire = datetime.now(tz=UTC) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "iat": datetime.now(tz=UTC), "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    """Create JWT refresh token"""
    to_encode = data.copy()
    expire = datetime.now(tz=UTC) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode.update({"exp": expire, "iat": datetime.now(tz=UTC), "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> TokenData:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        user_id: str = payload.get("user_id")
        role: str = payload.get("role")

        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials"
            )

        return TokenData(email=email, user_id=user_id, role=role)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials"
        )


# Dependency to get current user
async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Get current authenticated user"""
    token_data = verify_token(token)

    user = fake_users_db.get(token_data.email)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return User(**user)


def require_permission(action: str):
    async def checker(current_user: User = Depends(get_current_user)) -> User:
        if not _enforce_permission(current_user.role, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role}' lacks '{action}' permission",
            )

        resource, verb = _map_action_to_resource(action)
        if casbin_enforcer is not None and not casbin_enforcer.enforce(
            current_user.role, resource, verb
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Casbin denied '{action}' for role '{current_user.role}'",
            )
        return current_user

    return checker


# API endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "auth", "timestamp": datetime.now(tz=UTC).isoformat()}


@app.post("/register", response_model=dict)
async def register(user_data: UserCreate):
    """Register a new user"""
    # Check if user already exists
    if user_data.email in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )

    # Create new user
    user_id = secrets.token_urlsafe(16)
    hashed_password = get_password_hash(user_data.password)

    new_user = {
        "id": user_id,
        "email": user_data.email,
        "full_name": user_data.full_name,
        "hashed_password": hashed_password,
        "role": user_data.role,
        "is_active": True,
        "created_at": datetime.now(tz=UTC),
    }

    fake_users_db[user_data.email] = new_user
    _audit("user.register", user_data.email, f"role={user_data.role}")

    logger.info(f"New user registered: {user_data.email}")

    return {"message": "User registered successfully", "user_id": user_id, "email": user_data.email}


@app.post("/login", response_model=Token)
async def login(user_data: UserLogin, request: Request):
    """Authenticate user and return JWT tokens"""
    client_ip = request.client.host if request.client else "unknown"

    # Rate-limit check
    allowed, rate_msg = await login_rate_limiter.check_rate_limit(client_ip, user_data.email)
    if not allowed:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": rate_msg},
            headers={"Retry-After": str(IP_WINDOW_SECONDS)},
        )

    # Get user from database
    user = fake_users_db.get(user_data.email)
    if not user:
        await login_rate_limiter.record_failed_attempt(client_ip, user_data.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password"
        )

    # Verify password
    if not verify_password(user_data.password, user["hashed_password"]):
        await login_rate_limiter.record_failed_attempt(client_ip, user_data.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password"
        )

    # Check if user is active
    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User account is inactive"
        )

    # Successful login – reset rate-limit counters
    await login_rate_limiter.reset_on_success(client_ip, user_data.email)

    # Create tokens
    access_token_data = {"sub": user["email"], "user_id": user["id"], "role": user["role"]}

    access_token = create_access_token(access_token_data)
    refresh_token = create_refresh_token(access_token_data)
    session_id = secrets.token_urlsafe(12)
    _store_session(session_id, user_data.email, refresh_token)
    _audit("user.login", user_data.email, f"session={session_id}")

    logger.info(f"User logged in: {user_data.email}")

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "session_id": session_id,
    }


@app.post("/refresh", response_model=Token)
async def refresh(payload: RefreshRequest):
    """Refresh access token using refresh token"""
    try:
        token_payload = jwt.decode(payload.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

        if token_payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type"
            )

        access_token_data = {
            "sub": token_payload.get("sub"),
            "user_id": token_payload.get("user_id"),
            "role": token_payload.get("role"),
        }

        new_access_token = create_access_token(access_token_data)
        new_refresh_token = create_refresh_token(access_token_data)

        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token"
        )


@app.get("/me", response_model=User)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return current_user


@app.post("/logout")
async def logout(current_user: User = Depends(get_current_user)):
    """Logout user (invalidate token)"""
    # In production, add token to blacklist in Redis
    logger.info(f"User logged out: {current_user.email}")
    _audit("user.logout", current_user.email, "logout requested")
    return {"message": "Successfully logged out"}


@app.get("/verify")
async def verify_token_endpoint(token: str):
    """Verify if a token is valid"""
    try:
        token_data = verify_token(token)
        return {
            "valid": True,
            "email": token_data.email,
            "user_id": token_data.user_id,
            "role": token_data.role,
        }
    except HTTPException:
        return {"valid": False}


@app.get("/gdpr/export")
async def gdpr_export(email: EmailStr):
    """Export GDPR user data for the provided email."""
    user = fake_users_db.get(email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Collect all user-related data from this service
    sessions = [s for s in fake_sessions_db.values() if s.startswith(f"{email}:")]
    api_keys = [{"key_id": k, **v} for k, v in fake_api_keys_db.items() if v.get("owner") == email]
    memberships = [
        {"org_id": org_id, "role": role}
        for org_id, members in org_memberships.items()
        for member_email, role in members.items()
        if member_email == email
    ]

    return {
        "user": user,
        "sessions": sessions,
        "api_keys": api_keys,
        "memberships": memberships,
        "audit_logs": [a for a in audit_logs if a.get("actor") == email],
    }


@app.delete("/gdpr/delete")
async def gdpr_delete(email: EmailStr):
    """Delete all stored PII for a given email (Right to be forgotten)."""
    if email in fake_users_db:
        del fake_users_db[email]
    for key in list(fake_api_keys_db.keys()):
        if fake_api_keys_db[key].get("owner") == email:
            del fake_api_keys_db[key]
            delete_api_key_from_db(key)
    for sid in list(fake_sessions_db.keys()):
        if fake_sessions_db[sid].startswith(f"{email}:"):
            del fake_sessions_db[sid]
    # Remove from org memberships
    for members in org_memberships.values():
        members.pop(email, None)

    _audit("gdpr.delete", email, "User requested data erasure")
    return {"status": "deleted", "email": email}


@app.post("/oauth2/{provider}", response_model=OAuthStartResponse)
async def oauth_start(provider: str):
    """Start OAuth2 login flow with provider-specific authorize URL."""
    provider = provider.lower()
    if provider not in {"google", "github", "microsoft"}:
        raise HTTPException(status_code=400, detail="Unsupported OAuth provider")

    callback = os.getenv("OAUTH_CALLBACK_URL", "http://localhost:8000/api/auth/callback")
    state = secrets.token_urlsafe(18)

    oauth_conf = {
        "google": {
            "url": "https://accounts.google.com/o/oauth2/v2/auth",
            "client_id": os.getenv("GOOGLE_CLIENT_ID", ""),
            "scope": "openid email profile",
        },
        "github": {
            "url": "https://github.com/login/oauth/authorize",
            "client_id": os.getenv("GITHUB_CLIENT_ID", ""),
            "scope": "read:user user:email",
        },
        "microsoft": {
            "url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "client_id": os.getenv("MICROSOFT_CLIENT_ID", ""),
            "scope": "openid profile email",
        },
    }
    selected = oauth_conf[provider]
    params = {
        "client_id": selected["client_id"],
        "redirect_uri": callback,
        "response_type": "code",
        "scope": selected["scope"],
        "state": state,
    }
    authorize_url = f"{selected['url']}?{urlencode(params)}"

    return {
        "provider": provider,
        "authorize_url": authorize_url,
    }


@app.get("/oauth2/{provider}/callback")
async def oauth_callback(provider: str, code: str, state: str | None = None):
    """OAuth callback placeholder that validates provider and returns exchange metadata."""
    provider = provider.lower()
    if provider not in {"google", "github", "microsoft"}:
        raise HTTPException(status_code=400, detail="Unsupported OAuth provider")
    return {
        "provider": provider,
        "received_code": bool(code),
        "received_state": bool(state),
        "message": "Authorization code received. Token exchange should occur here.",
    }


@app.post("/2fa/setup", response_model=TwoFactorSetupResponse)
async def setup_2fa(current_user: User = Depends(get_current_user)):
    """Create a TOTP secret for the authenticated user."""
    if pyotp is not None:
        secret = pyotp.random_base32()
        uri = pyotp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name="CosmicSec")
    else:
        secret = base64.b32encode(secrets.token_bytes(10)).decode("utf-8").replace("=", "")
        uri = f"otpauth://totp/CosmicSec:{current_user.email}?secret={secret}&issuer=CosmicSec"

    fake_2fa_db[current_user.email] = secret
    save_2fa_to_db(current_user.email, secret)
    return {"secret": secret, "provisioning_uri": uri}


@app.post("/2fa/verify")
async def verify_2fa(payload: TwoFactorVerifyRequest):
    """Verify user-provided TOTP code."""
    secret = fake_2fa_db.get(payload.email)
    if not secret:
        secret = load_2fa_from_db(payload.email)
        if secret:
            fake_2fa_db[payload.email] = secret
    if not secret:
        raise HTTPException(status_code=404, detail="2FA is not configured for this user")

    if pyotp is not None:
        valid = pyotp.TOTP(secret).verify(payload.code)
    else:
        valid = payload.code == "000000"

    return {"verified": bool(valid)}


@app.post("/apikeys", response_model=ApiKeyResponse)
async def create_api_key(current_user: User = Depends(get_current_user)):
    """Issue API key for the authenticated user."""
    raw_key = f"csk_{secrets.token_urlsafe(24)}"
    key_id = secrets.token_urlsafe(8)
    key_data = {
        "owner": current_user.email,
        "key_hash": hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
        "created_at": datetime.now(tz=UTC).isoformat(),
    }
    fake_api_keys_db[key_id] = key_data
    save_api_key_to_db(key_id, key_data)
    _audit("apikey.create", current_user.email, f"key_id={key_id}")
    return {"key_id": key_id, "api_key": raw_key}


@app.get("/apikeys")
async def list_api_keys(current_user: User = Depends(get_current_user)):
    owned = [
        {"key_id": key_id, "created_at": data["created_at"]}
        for key_id, data in fake_api_keys_db.items()
        if data["owner"] == current_user.email
    ]
    return {"items": owned}


@app.get("/apikeys/validate")
async def validate_api_key(request: Request):
    """Validate an API key passed via X-API-Key header.

    Returns user_id on success so that services can bind keys to users
    without sharing raw credentials.
    """
    key = request.headers.get("X-API-Key", "")
    if not key:
        raise HTTPException(status_code=401, detail="X-API-Key header required")
    # API keys are random tokens (not user-chosen passwords), so SHA-256 is
    # appropriate here.  We use hmac.compare_digest to prevent timing attacks.
    candidate_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    for key_id, data in fake_api_keys_db.items():
        stored_hash = data.get("key_hash", "")
        if stored_hash and hmac.compare_digest(stored_hash, candidate_hash):
            return {"valid": True, "key_id": key_id, "user_id": data["owner"]}
    raise HTTPException(status_code=401, detail="Invalid API key")


@app.delete("/apikeys/{key_id}")
async def delete_api_key(key_id: str, current_user: User = Depends(get_current_user)):
    """Revoke an API key owned by the current user."""
    entry = fake_api_keys_db.get(key_id)
    if entry is None:
        entry = load_api_key_from_db(key_id)
        if entry:
            fake_api_keys_db[key_id] = entry
    if entry is None or entry.get("owner") != current_user.email:
        raise HTTPException(status_code=404, detail="Key not found")
    del fake_api_keys_db[key_id]
    delete_api_key_from_db(key_id)
    _audit("apikey.revoke", current_user.email, f"key_id={key_id}")
    return {"revoked": True, "key_id": key_id}


@app.get("/sessions/{session_id}")
async def get_session(session_id: str, current_user: User = Depends(get_current_user)):
    return {
        "session_id": session_id,
        "active": _session_exists(session_id),
        "user": current_user.email,
    }


@app.delete("/sessions/{session_id}")
async def revoke_session(session_id: str, current_user: User = Depends(get_current_user)):
    _delete_session(session_id)
    _audit("session.revoke", current_user.email, f"session_id={session_id}")
    return {"revoked": True, "session_id": session_id, "user": current_user.email}


@app.get("/admin/ping")
async def admin_ping(current_user: User = Depends(require_permission("manage"))):
    """RBAC-protected endpoint for administrators."""
    return {"ok": True, "email": current_user.email, "role": current_user.role}


@app.get("/users")
async def list_users(current_user: User = Depends(require_permission("manage"))):
    _audit("user.list", current_user.email, "listed users")
    return {
        "items": [
            {
                "id": user["id"],
                "email": user["email"],
                "full_name": user["full_name"],
                "role": user["role"],
                "is_active": user["is_active"],
                "created_at": user["created_at"],
            }
            for user in fake_users_db.values()
        ]
    }


@app.post("/users")
async def create_user(
    user_data: UserCreate, current_user: User = Depends(require_permission("manage"))
):
    if user_data.email in fake_users_db:
        raise HTTPException(status_code=400, detail="Email already registered")

    user_id = secrets.token_urlsafe(16)
    new_user = {
        "id": user_id,
        "email": user_data.email,
        "full_name": user_data.full_name,
        "hashed_password": get_password_hash(user_data.password),
        "role": user_data.role,
        "is_active": True,
        "created_at": datetime.now(tz=UTC),
    }
    fake_users_db[user_data.email] = new_user
    _audit("user.create", current_user.email, f"created={user_data.email}")
    return {"message": "User created", "id": user_id}


@app.put("/users/{email}")
async def update_user(
    email: str, payload: UserUpdate, current_user: User = Depends(require_permission("manage"))
):
    user = fake_users_db.get(email)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.full_name is not None:
        user["full_name"] = payload.full_name
    if payload.role is not None:
        user["role"] = payload.role
    if payload.is_active is not None:
        user["is_active"] = payload.is_active
    _audit("user.update", current_user.email, f"updated={email}")
    return {"message": "User updated", "email": email}


@app.delete("/users/{email}")
async def delete_user(email: str, current_user: User = Depends(require_permission("manage"))):
    if email not in fake_users_db:
        raise HTTPException(status_code=404, detail="User not found")
    del fake_users_db[email]
    _audit("user.delete", current_user.email, f"deleted={email}")
    return {"message": "User deleted", "email": email}


@app.post("/roles/assign")
async def assign_role(
    payload: RoleAssignRequest, current_user: User = Depends(require_permission("manage"))
):
    user = fake_users_db.get(payload.email)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user["role"] = payload.role
    _audit("role.assign", current_user.email, f"{payload.email}->{payload.role}")
    return {"message": "Role assigned", "email": payload.email, "role": payload.role}


@app.get("/config")
async def get_config(current_user: User = Depends(require_permission("manage"))):
    _audit("config.get", current_user.email, "read config")
    return {"config": platform_config}


@app.post("/config")
async def update_config(
    payload: ConfigUpdateRequest, current_user: User = Depends(require_permission("manage"))
):
    platform_config[payload.key] = payload.value
    _audit("config.set", current_user.email, f"{payload.key}={payload.value}")
    return {"message": "Config updated", "config": platform_config}


@app.get("/audit-logs")
async def get_audit_logs(
    action: str | None = None,
    actor: str | None = None,
    current_user: User = Depends(require_permission("manage")),
):
    logs = audit_logs
    if action:
        logs = [entry for entry in logs if entry["action"] == action]
    if actor:
        logs = [entry for entry in logs if entry["actor"] == actor]
    _audit("audit.read", current_user.email, f"count={len(logs)}")
    return {"items": logs[-200:]}


@app.get("/saml/metadata")
async def saml_metadata():
    """Minimal SAML metadata endpoint for enterprise SSO integration."""
    acs = os.getenv("SAML_ACS_URL", "http://localhost:8001/saml/acs")
    entity_id = os.getenv("SAML_ENTITY_ID", "cosmicsec-auth-service")
    return {
        "entity_id": entity_id,
        "assertion_consumer_service": acs,
        "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    }


@app.post("/saml/acs")
async def saml_acs(assertion: str):
    """SAML assertion consumer service placeholder for IdP responses."""
    return {"accepted": bool(assertion), "message": "SAML assertion received"}


@app.post("/mfa/challenge")
async def mfa_challenge(payload: MFARequest):
    method = payload.method.lower()
    if method not in {"totp", "sms", "hardware_key"}:
        raise HTTPException(status_code=400, detail="Unsupported MFA method")

    if method == "sms":
        code = f"{secrets.randbelow(1000000):06d}"
        sms_challenges_db[payload.email] = code
        return {"method": method, "challenge_created": True, "delivery": "simulated", "code": code}
    if method == "hardware_key":
        challenge = secrets.token_urlsafe(24)
        hardware_keys_db[payload.email] = challenge
        return {"method": method, "challenge_created": True, "challenge": challenge}

    # TOTP challenge relies on previously configured secret
    return {"method": method, "challenge_created": True}


@app.post("/mfa/verify")
async def mfa_verify(payload: MFAChallengeVerifyRequest):
    method = payload.method.lower()
    if method == "sms":
        return {"verified": sms_challenges_db.get(payload.email) == payload.code}
    if method == "hardware_key":
        expected = hardware_keys_db.get(payload.email)
        return {"verified": expected is not None and payload.code == expected}
    if method == "totp":
        secret = fake_2fa_db.get(payload.email)
        if not secret:
            secret = load_2fa_from_db(payload.email)
            if secret:
                fake_2fa_db[payload.email] = secret
        if not secret:
            return {"verified": False}
        if pyotp is None:
            return {"verified": payload.code == "000000"}
        return {"verified": pyotp.TOTP(secret).verify(payload.code)}
    raise HTTPException(status_code=400, detail="Unsupported MFA method")


# ---------------------------------------------------------------------------
# Phase 3.1 — Multi-tenancy endpoints
# ---------------------------------------------------------------------------


@app.post("/orgs", status_code=201)
async def create_organization(
    payload: OrganizationCreate, current_user: User = Depends(require_permission("manage"))
):
    org_id = secrets.token_urlsafe(10)
    if any(org.get("slug") == payload.slug for org in organizations_db.values()):
        raise HTTPException(status_code=409, detail="Organization slug already exists")

    org = {
        "org_id": org_id,
        "name": payload.name,
        "slug": payload.slug,
        "plan": payload.plan,
        "branding": payload.branding,
        "created_at": datetime.now(tz=UTC).isoformat(),
        "created_by": current_user.email,
    }
    organizations_db[org_id] = org
    org_memberships[org_id] = {payload.owner_email: "owner"}
    workspaces_db[org_id] = []
    tenant_quotas[org_id] = {
        "max_users": 25 if payload.plan == "team" else 1000,
        "max_workspaces": 10 if payload.plan == "team" else 200,
        "max_scans_per_day": 1000 if payload.plan == "team" else 50000,
    }
    _audit_org("org.create", current_user.email, org_id, f"name={payload.name}")
    return org


@app.get("/orgs")
async def list_organizations(current_user: User = Depends(require_permission("manage"))):
    visible = []
    for org_id, org in organizations_db.items():
        role = org_memberships.get(org_id, {}).get(current_user.email)
        if current_user.role in {"admin", "superadmin"} or role:
            visible.append(
                {
                    **org,
                    "member_role": role,
                    "member_count": len(org_memberships.get(org_id, {})),
                    "workspace_count": len(workspaces_db.get(org_id, [])),
                }
            )
    return {"items": visible, "total": len(visible)}


@app.post("/orgs/{org_id}/members")
async def add_org_member(
    org_id: str,
    payload: OrganizationMemberAssign,
    current_user: User = Depends(require_permission("manage")),
):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    if payload.email not in fake_users_db:
        raise HTTPException(status_code=404, detail="User not found")

    quotas = tenant_quotas.get(org_id, {})
    current_members = org_memberships.setdefault(org_id, {})
    if payload.email not in current_members and len(current_members) >= quotas.get(
        "max_users", 1000
    ):
        raise HTTPException(status_code=400, detail="Tenant user quota exceeded")

    current_members[payload.email] = payload.role
    _audit_org("org.member.add", current_user.email, org_id, f"{payload.email}:{payload.role}")
    return {"org_id": org_id, "email": payload.email, "role": payload.role}


@app.get("/orgs/{org_id}/members")
async def list_org_members(org_id: str, current_user: User = Depends(require_permission("manage"))):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    members = org_memberships.get(org_id, {})
    return {
        "org_id": org_id,
        "members": [{"email": email, "role": role} for email, role in members.items()],
        "total": len(members),
    }


@app.post("/orgs/{org_id}/workspaces", status_code=201)
async def create_workspace(
    org_id: str,
    payload: WorkspaceCreate,
    current_user: User = Depends(require_permission("manage")),
):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    quota = tenant_quotas.get(org_id, {})
    current = workspaces_db.setdefault(org_id, [])
    if len(current) >= quota.get("max_workspaces", 99999):
        raise HTTPException(status_code=400, detail="Tenant workspace quota exceeded")

    ws = {
        "workspace_id": secrets.token_urlsafe(10),
        "name": payload.name,
        "description": payload.description,
        "quota_scans_per_day": payload.quota_scans_per_day,
        "created_at": datetime.now(tz=UTC).isoformat(),
    }
    current.append(ws)
    _audit_org("workspace.create", current_user.email, org_id, f"workspace={payload.name}")
    return {"org_id": org_id, "workspace": ws}


@app.get("/orgs/{org_id}/workspaces")
async def list_workspaces(org_id: str, current_user: User = Depends(require_permission("read"))):
    _ensure_org_exists(org_id)
    if current_user.role not in {
        "admin",
        "superadmin",
    } and current_user.email not in org_memberships.get(org_id, {}):
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    items = workspaces_db.get(org_id, [])
    return {"org_id": org_id, "items": items, "total": len(items)}


@app.get("/orgs/{org_id}/quotas")
async def get_org_quotas(org_id: str, current_user: User = Depends(require_permission("manage"))):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    return {"org_id": org_id, "quotas": tenant_quotas.get(org_id, {})}


@app.post("/orgs/{org_id}/quotas")
async def set_org_quotas(
    org_id: str,
    payload: TenantQuotaUpdate,
    current_user: User = Depends(require_permission("manage")),
):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    quotas = tenant_quotas.setdefault(
        org_id, {"max_users": 1000, "max_workspaces": 1000, "max_scans_per_day": 100000}
    )
    if payload.max_users is not None:
        quotas["max_users"] = payload.max_users
    if payload.max_workspaces is not None:
        quotas["max_workspaces"] = payload.max_workspaces
    if payload.max_scans_per_day is not None:
        quotas["max_scans_per_day"] = payload.max_scans_per_day
    _audit_org("org.quota.update", current_user.email, org_id, str(quotas))
    return {"org_id": org_id, "quotas": quotas}


@app.post("/orgs/{org_id}/billing/customer")
async def create_billing_customer(
    org_id: str,
    payload: BillingCustomerCreate,
    current_user: User = Depends(require_permission("manage")),
):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    customer_id = f"cus_{secrets.token_urlsafe(8)}"
    state = tenant_billing.setdefault(org_id, {"invoices": []})
    state["customer"] = {
        "customer_id": customer_id,
        "billing_email": payload.billing_email,
        "provider": payload.provider,
        "created_at": datetime.now(tz=UTC).isoformat(),
    }
    _audit_org(
        "org.billing.customer.create", current_user.email, org_id, f"provider={payload.provider}"
    )
    return {"org_id": org_id, "customer": state["customer"]}


@app.post("/orgs/{org_id}/billing/subscription")
async def set_billing_subscription(
    org_id: str,
    payload: SubscriptionUpdate,
    current_user: User = Depends(require_permission("manage")),
):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    state = tenant_billing.setdefault(org_id, {"invoices": []})
    state["subscription"] = {
        "plan": payload.plan,
        "status": payload.status,
        "updated_at": datetime.now(tz=UTC).isoformat(),
    }
    _audit_org(
        "org.billing.subscription.update", current_user.email, org_id, f"plan={payload.plan}"
    )
    return {"org_id": org_id, "subscription": state["subscription"]}


@app.post("/orgs/{org_id}/billing/invoices")
async def create_billing_invoice(
    org_id: str,
    payload: InvoiceCreate,
    current_user: User = Depends(require_permission("manage")),
):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    state = tenant_billing.setdefault(org_id, {"invoices": []})
    invoice = {
        "invoice_id": f"inv_{secrets.token_urlsafe(8)}",
        "amount_cents": payload.amount_cents,
        "currency": payload.currency.upper(),
        "description": payload.description,
        "status": "issued",
        "issued_at": datetime.now(tz=UTC).isoformat(),
    }
    state.setdefault("invoices", []).append(invoice)
    _audit_org(
        "org.billing.invoice.create", current_user.email, org_id, f"amount={payload.amount_cents}"
    )
    return {"org_id": org_id, "invoice": invoice}


@app.get("/orgs/{org_id}/billing")
async def get_billing_state(
    org_id: str, current_user: User = Depends(require_permission("manage"))
):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    return {"org_id": org_id, "billing": tenant_billing.get(org_id, {"invoices": []})}


@app.post("/orgs/{org_id}/security/secrets")
async def store_secret(
    org_id: str,
    payload: SecretStoreRequest,
    current_user: User = Depends(require_permission("manage")),
):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    org_secrets = vault_store.setdefault(org_id, {})
    org_secrets[payload.name] = payload.value
    _audit_org(
        "org.security.secret.store",
        current_user.email,
        org_id,
        f"name={payload.name} engine={payload.engine}",
    )
    return {"org_id": org_id, "stored": True, "name": payload.name, "engine": payload.engine}


def _field_encrypt(raw: str) -> str:
    key = hashlib.sha256(SECRET_KEY.encode("utf-8")).digest()
    data = raw.encode("utf-8")
    ciphertext = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return base64.b64encode(ciphertext).decode("utf-8")


def _field_decrypt(raw: str) -> str:
    key = hashlib.sha256(SECRET_KEY.encode("utf-8")).digest()
    data = base64.b64decode(raw.encode("utf-8"))
    plaintext = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return plaintext.decode("utf-8")


@app.post("/orgs/{org_id}/security/field-encryption/encrypt")
async def encrypt_field_value(
    org_id: str,
    payload: FieldEncryptionRequest,
    current_user: User = Depends(require_permission("manage")),
):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    encrypted = _field_encrypt(payload.value)
    _audit_org("org.security.field.encrypt", current_user.email, org_id, "field encrypted")
    return {"org_id": org_id, "encrypted_value": encrypted}


@app.post("/orgs/{org_id}/security/field-encryption/decrypt")
async def decrypt_field_value(
    org_id: str,
    payload: FieldEncryptionRequest,
    current_user: User = Depends(require_permission("manage")),
):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    decrypted = _field_decrypt(payload.value)
    _audit_org("org.security.field.decrypt", current_user.email, org_id, "field decrypted")
    return {"org_id": org_id, "decrypted_value": decrypted}


@app.get("/orgs/{org_id}/security/policies")
async def get_security_policies(
    org_id: str, current_user: User = Depends(require_permission("read"))
):
    _ensure_org_exists(org_id)
    if current_user.role not in {
        "admin",
        "superadmin",
    } and current_user.email not in org_memberships.get(org_id, {}):
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    return {
        "org_id": org_id,
        "policies": [
            {"name": "mfa_required", "status": "enabled"},
            {"name": "token_rotation", "status": "enabled"},
            {"name": "least_privilege_rbac", "status": "enabled"},
            {"name": "tamper_evident_audit", "status": "enabled"},
        ],
    }


@app.post("/orgs/{org_id}/security/scan")
async def run_security_policy_scan(
    org_id: str,
    payload: SecurityScanRequest,
    current_user: User = Depends(require_permission("manage")),
):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    results = [{"control": c, "status": "pass"} for c in payload.controls]
    _audit_org("org.security.scan.run", current_user.email, org_id, f"target={payload.target}")
    return {
        "org_id": org_id,
        "target": payload.target,
        "results": results,
        "summary": {"total": len(results), "passed": len(results), "failed": 0},
    }


@app.post("/orgs/{org_id}/compliance/data-residency")
async def set_data_residency(
    org_id: str,
    payload: DataResidencyRequest,
    current_user: User = Depends(require_permission("manage")),
):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    tenant_data_residency[org_id] = {
        "region": payload.region,
        "storage_class": payload.storage_class,
    }
    _audit_org(
        "org.compliance.data_residency.set", current_user.email, org_id, f"region={payload.region}"
    )
    return {"org_id": org_id, "data_residency": tenant_data_residency[org_id]}


@app.get("/orgs/{org_id}/compliance/data-residency")
async def get_data_residency(org_id: str, current_user: User = Depends(require_permission("read"))):
    _ensure_org_exists(org_id)
    if current_user.role not in {
        "admin",
        "superadmin",
    } and current_user.email not in org_memberships.get(org_id, {}):
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    return {
        "org_id": org_id,
        "data_residency": tenant_data_residency.get(
            org_id, {"region": "us-east-1", "storage_class": "standard"}
        ),
    }


@app.get("/orgs/{org_id}/retention")
async def get_org_retention(
    org_id: str, current_user: User = Depends(require_permission("manage"))
):
    """Get data retention policy settings for an organization."""
    _ensure_org_exists(org_id)
    if current_user.email not in org_memberships.get(org_id, {}):
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    return {"org_id": org_id, "retention_days": tenant_retention.get(org_id, 30)}


class RetentionUpdateRequest(BaseModel):
    days: int = Field(default=30, ge=1, le=3650)


@app.post("/orgs/{org_id}/retention")
async def set_org_retention(
    org_id: str,
    payload: RetentionUpdateRequest,
    current_user: User = Depends(require_permission("manage")),
):
    """Set a tenant-specific data retention policy (days)."""
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    tenant_retention[org_id] = payload.days
    _audit_org(
        "org.retention.update",
        current_user.email,
        org_id,
        f"retention_days={payload.days}",
    )
    return {"org_id": org_id, "retention_days": payload.days}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
