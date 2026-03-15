"""
CosmicSec Authentication Service
Handles user authentication, JWT tokens, OAuth2, and session management
"""
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
import os
import secrets
import logging
import hashlib
import base64
from pathlib import Path
from urllib.parse import urlencode

try:
    import redis
except Exception:  # pragma: no cover - optional dependency at runtime
    redis = None

try:
    import pyotp
except Exception:  # pragma: no cover - optional dependency at runtime
    pyotp = None

try:
    import casbin
except Exception:  # pragma: no cover - optional dependency at runtime
    casbin = None

app = FastAPI(
    title="CosmicSec Auth Service",
    description="Authentication and authorization service for GuardAxisSphere",
    version="1.0.0"
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

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
    email: Optional[str] = None
    user_id: Optional[str] = None
    role: Optional[str] = None


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
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


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
    branding: Dict[str, str] = Field(default_factory=dict)


class WorkspaceCreate(BaseModel):
    name: str
    description: Optional[str] = None
    quota_scans_per_day: int = Field(default=100, ge=1, le=100000)


class OrganizationMemberAssign(BaseModel):
    email: EmailStr
    role: str = "member"  # owner | admin | member


class TenantQuotaUpdate(BaseModel):
    max_users: Optional[int] = Field(default=None, ge=1, le=100000)
    max_workspaces: Optional[int] = Field(default=None, ge=1, le=100000)
    max_scans_per_day: Optional[int] = Field(default=None, ge=1, le=1000000)


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
tenant_billing: Dict[str, Dict[str, Any]] = {}
tenant_retention: Dict[str, int] = {}  # days


def _hash_audit_entry(entry: Dict[str, Any], previous_hash: Optional[str]) -> str:
    """Generate a tamper-evident hash chain for audit logs."""
    import hashlib, json

    payload = {
        **entry,
        "previous_hash": previous_hash or "",
    }
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def _audit_entry(action: str, actor: str, detail: str, org_id: Optional[str] = None) -> None:
    ts = datetime.utcnow().isoformat()
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
    now = datetime.utcnow()
    kept: List[Dict[str, Any]] = []
    for entry in audit_logs:
        org = entry.get("org_id")
        days = tenant_retention.get(org, 30)
        try:
            ts = datetime.fromisoformat(entry["timestamp"])
        except Exception:
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

# Multi-tenant state (in-memory; DB in production)
organizations_db: Dict[str, Dict] = {}
org_memberships: Dict[str, Dict[str, str]] = {}  # org_id -> {email: role}
workspaces_db: Dict[str, List[Dict]] = {}  # org_id -> workspace list
tenant_quotas: Dict[str, Dict[str, int]] = {}  # org_id -> quotas

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


def _ensure_org_exists(org_id: str) -> Dict:
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
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash password using bcrypt"""
    return pwd_context.hash(password)


# JWT utilities
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    })
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    """Create JWT refresh token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh"
    })
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
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )

        return TokenData(email=email, user_id=user_id, role=role)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )


# Dependency to get current user
async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Get current authenticated user"""
    token_data = verify_token(token)

    user = fake_users_db.get(token_data.email)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    return User(**user)


def require_permission(action: str):
    async def checker(current_user: User = Depends(get_current_user)) -> User:
        if not _enforce_permission(current_user.role, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role}' lacks '{action}' permission",
            )

        resource, verb = _map_action_to_resource(action)
        if casbin_enforcer is not None and not casbin_enforcer.enforce(current_user.role, resource, verb):
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
    return {
        "status": "healthy",
        "service": "auth",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/register", response_model=dict)
async def register(user_data: UserCreate):
    """Register a new user"""
    # Check if user already exists
    if user_data.email in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
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
        "created_at": datetime.utcnow()
    }

    fake_users_db[user_data.email] = new_user
    _audit("user.register", user_data.email, f"role={user_data.role}")

    logger.info(f"New user registered: {user_data.email}")

    return {
        "message": "User registered successfully",
        "user_id": user_id,
        "email": user_data.email
    }


@app.post("/login", response_model=Token)
async def login(user_data: UserLogin):
    """Authenticate user and return JWT tokens"""
    # Get user from database
    user = fake_users_db.get(user_data.email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )

    # Verify password
    if not verify_password(user_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )

    # Check if user is active
    if not user["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )

    # Create tokens
    access_token_data = {
        "sub": user["email"],
        "user_id": user["id"],
        "role": user["role"]
    }

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
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )

        access_token_data = {
            "sub": token_payload.get("sub"),
            "user_id": token_payload.get("user_id"),
            "role": token_payload.get("role")
        }

        new_access_token = create_access_token(access_token_data)
        new_refresh_token = create_refresh_token(access_token_data)

        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
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
            "role": token_data.role
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
    api_keys = [
        {"key_id": k, **v} for k, v in fake_api_keys_db.items() if v.get("owner") == email
    ]
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
async def oauth_callback(provider: str, code: str, state: Optional[str] = None):
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
    return {"secret": secret, "provisioning_uri": uri}


@app.post("/2fa/verify")
async def verify_2fa(payload: TwoFactorVerifyRequest):
    """Verify user-provided TOTP code."""
    secret = fake_2fa_db.get(payload.email)
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
    fake_api_keys_db[key_id] = {
        "owner": current_user.email,
        "key_hash": hashlib.sha256(raw_key.encode("utf-8")).hexdigest(),
        "created_at": datetime.utcnow().isoformat(),
    }
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
async def create_user(user_data: UserCreate, current_user: User = Depends(require_permission("manage"))):
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
        "created_at": datetime.utcnow(),
    }
    fake_users_db[user_data.email] = new_user
    _audit("user.create", current_user.email, f"created={user_data.email}")
    return {"message": "User created", "id": user_id}


@app.put("/users/{email}")
async def update_user(email: str, payload: UserUpdate, current_user: User = Depends(require_permission("manage"))):
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
async def assign_role(payload: RoleAssignRequest, current_user: User = Depends(require_permission("manage"))):
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
async def update_config(payload: ConfigUpdateRequest, current_user: User = Depends(require_permission("manage"))):
    platform_config[payload.key] = payload.value
    _audit("config.set", current_user.email, f"{payload.key}={payload.value}")
    return {"message": "Config updated", "config": platform_config}


@app.get("/audit-logs")
async def get_audit_logs(
    action: Optional[str] = None,
    actor: Optional[str] = None,
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
            return {"verified": False}
        if pyotp is None:
            return {"verified": payload.code == "000000"}
        return {"verified": pyotp.TOTP(secret).verify(payload.code)}
    raise HTTPException(status_code=400, detail="Unsupported MFA method")


# ---------------------------------------------------------------------------
# Phase 3.1 — Multi-tenancy endpoints
# ---------------------------------------------------------------------------

@app.post("/orgs", status_code=201)
async def create_organization(payload: OrganizationCreate, current_user: User = Depends(require_permission("manage"))):
    org_id = secrets.token_urlsafe(10)
    if any(org.get("slug") == payload.slug for org in organizations_db.values()):
        raise HTTPException(status_code=409, detail="Organization slug already exists")

    org = {
        "org_id": org_id,
        "name": payload.name,
        "slug": payload.slug,
        "plan": payload.plan,
        "branding": payload.branding,
        "created_at": datetime.utcnow().isoformat(),
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
            visible.append({
                **org,
                "member_role": role,
                "member_count": len(org_memberships.get(org_id, {})),
                "workspace_count": len(workspaces_db.get(org_id, [])),
            })
    return {"items": visible, "total": len(visible)}


@app.post("/orgs/{org_id}/members")
async def add_org_member(org_id: str, payload: OrganizationMemberAssign, current_user: User = Depends(require_permission("manage"))):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    if payload.email not in fake_users_db:
        raise HTTPException(status_code=404, detail="User not found")

    quotas = tenant_quotas.get(org_id, {})
    current_members = org_memberships.setdefault(org_id, {})
    if payload.email not in current_members and len(current_members) >= quotas.get("max_users", 1000):
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
async def create_workspace(org_id: str, payload: WorkspaceCreate, current_user: User = Depends(require_permission("manage"))):
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
        "created_at": datetime.utcnow().isoformat(),
    }
    current.append(ws)
    _audit_org("workspace.create", current_user.email, org_id, f"workspace={payload.name}")
    return {"org_id": org_id, "workspace": ws}


@app.get("/orgs/{org_id}/workspaces")
async def list_workspaces(org_id: str, current_user: User = Depends(require_permission("read"))):
    _ensure_org_exists(org_id)
    if current_user.role not in {"admin", "superadmin"} and current_user.email not in org_memberships.get(org_id, {}):
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    items = workspaces_db.get(org_id, [])
    return {"org_id": org_id, "items": items, "total": len(items)}


@app.get("/orgs/{org_id}/quotas")
async def get_org_quotas(org_id: str, current_user: User = Depends(require_permission("manage"))):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    return {"org_id": org_id, "quotas": tenant_quotas.get(org_id, {})}


@app.post("/orgs/{org_id}/quotas")
async def set_org_quotas(org_id: str, payload: TenantQuotaUpdate, current_user: User = Depends(require_permission("manage"))):
    _ensure_org_exists(org_id)
    _require_org_admin(org_id, current_user.email)
    quotas = tenant_quotas.setdefault(org_id, {"max_users": 1000, "max_workspaces": 1000, "max_scans_per_day": 100000})
    if payload.max_users is not None:
        quotas["max_users"] = payload.max_users
    if payload.max_workspaces is not None:
        quotas["max_workspaces"] = payload.max_workspaces
    if payload.max_scans_per_day is not None:
        quotas["max_scans_per_day"] = payload.max_scans_per_day
    _audit_org("org.quota.update", current_user.email, org_id, str(quotas))
    return {"org_id": org_id, "quotas": quotas}


@app.get("/orgs/{org_id}/retention")
async def get_org_retention(org_id: str, current_user: User = Depends(require_permission("manage"))):
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
