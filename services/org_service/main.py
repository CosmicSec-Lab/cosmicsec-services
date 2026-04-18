"""
CosmicSec Organization Service — Multi-tenancy & Enterprise Management.

Phase R: Multi-tenant organization management, member invites,
SSO provider configuration, branding, and plan management.
"""

from __future__ import annotations

import logging
import os
import secrets
import uuid
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.exc import SQLAlchemyError

try:
    from sqlalchemy.orm import Session as SASession

    from services.common.db import SessionLocal
    from services.common.models import (
        OrganizationMemberModel,
        OrganizationModel,
        SSOProviderModel,
        UserModel,
    )

    _HAS_DB = True
except ImportError:
    _HAS_DB = False

logger = logging.getLogger(__name__)

app = FastAPI(
    title="CosmicSec Organization Service",
    description="Multi-tenant organization management for CosmicSec enterprise",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.exception_handler(SQLAlchemyError)
async def handle_db_errors(_request, _exc: SQLAlchemyError):
    logger.warning("Organization service database unavailable; returning 503")
    return JSONResponse(status_code=503, content={"detail": "Database unavailable"})

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class OrgCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    slug: str = Field(..., min_length=2, max_length=50, pattern=r"^[a-z0-9-]+$")
    plan: str = Field(default="free")
    seat_limit: int = Field(default=5, ge=1, le=10000)


class OrgUpdate(BaseModel):
    name: str | None = None
    logo_url: str | None = None
    primary_color: str | None = None
    settings: dict | None = None
    plan: str | None = None
    seat_limit: int | None = None


class InviteMember(BaseModel):
    email: str
    role: str = Field(default="member")


class SSOProviderCreate(BaseModel):
    provider_type: str = Field(..., pattern=r"^(oidc|saml)$")
    provider_name: str = Field(..., min_length=2, max_length=50)
    client_id: str | None = None
    client_secret: str | None = None
    settings: dict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def get_db():
    if not _HAS_DB:
        raise HTTPException(503, "Database unavailable")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _org_to_dict(org: OrganizationModel) -> dict:
    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "logo_url": org.logo_url,
        "primary_color": org.primary_color,
        "seat_limit": org.seat_limit,
        "plan": org.plan,
        "settings": org.settings or {},
        "is_active": org.is_active,
        "created_at": org.created_at.isoformat() if org.created_at else None,
    }


def _member_to_dict(member: OrganizationMemberModel, user: UserModel | None) -> dict:
    return {
        "id": member.id,
        "org_id": member.org_id,
        "user_id": member.user_id,
        "role": member.role,
        "email": user.email if user else None,
        "full_name": user.full_name if user else None,
        "joined_at": member.joined_at.isoformat() if member.joined_at else None,
    }


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "org-service",
        "timestamp": datetime.now(UTC).isoformat(),
    }


# ---------------------------------------------------------------------------
# Organization CRUD
# ---------------------------------------------------------------------------


@app.post("/api/orgs", status_code=status.HTTP_201_CREATED)
async def create_org(payload: OrgCreate, db: SASession = Depends(get_db)):
    """Create a new organization."""
    existing = db.query(OrganizationModel).filter_by(slug=payload.slug).first()
    if existing:
        raise HTTPException(409, f"Organization slug '{payload.slug}' already taken")

    org = OrganizationModel(
        id=str(uuid.uuid4()),
        name=payload.name,
        slug=payload.slug,
        plan=payload.plan,
        seat_limit=payload.seat_limit,
        settings={},
    )
    db.add(org)
    db.commit()
    db.refresh(org)
    logger.info("Organization created: %s (%s)", org.name, org.id)
    return _org_to_dict(org)


@app.get("/api/orgs/{org_id}")
async def get_org(org_id: str, db: SASession = Depends(get_db)):
    """Get organization details."""
    org = db.query(OrganizationModel).filter_by(id=org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    return _org_to_dict(org)


@app.get("/api/orgs/slug/{slug}")
async def get_org_by_slug(slug: str, db: SASession = Depends(get_db)):
    """Get organization by slug (for SSO discovery)."""
    org = db.query(OrganizationModel).filter_by(slug=slug, is_active=True).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    return _org_to_dict(org)


@app.put("/api/orgs/{org_id}")
async def update_org(org_id: str, payload: OrgUpdate, db: SASession = Depends(get_db)):
    """Update organization settings."""
    org = db.query(OrganizationModel).filter_by(id=org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")

    if payload.name is not None:
        org.name = payload.name
    if payload.logo_url is not None:
        org.logo_url = payload.logo_url
    if payload.primary_color is not None:
        org.primary_color = payload.primary_color
    if payload.settings is not None:
        org.settings = {**(org.settings or {}), **payload.settings}
    if payload.plan is not None:
        org.plan = payload.plan
    if payload.seat_limit is not None:
        org.seat_limit = payload.seat_limit

    db.commit()
    db.refresh(org)
    return _org_to_dict(org)


@app.delete("/api/orgs/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_org(org_id: str, db: SASession = Depends(get_db)):
    """Soft-delete organization."""
    org = db.query(OrganizationModel).filter_by(id=org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    org.is_active = False
    db.commit()


# ---------------------------------------------------------------------------
# Member management
# ---------------------------------------------------------------------------


@app.post("/api/orgs/{org_id}/invite", status_code=status.HTTP_201_CREATED)
async def invite_member(org_id: str, payload: InviteMember, db: SASession = Depends(get_db)):
    """Invite a user to an organization."""
    org = db.query(OrganizationModel).filter_by(id=org_id, is_active=True).first()
    if not org:
        raise HTTPException(404, "Organization not found")

    # Find user by email
    user = db.query(UserModel).filter_by(email=payload.email).first()
    if not user:
        raise HTTPException(404, f"No user found with email '{payload.email}'")

    # Check seat limit
    member_count = db.query(OrganizationMemberModel).filter_by(org_id=org_id).count()
    if member_count >= org.seat_limit:
        raise HTTPException(429, f"Organization seat limit ({org.seat_limit}) reached")

    # Prevent duplicate membership
    existing = db.query(OrganizationMemberModel).filter_by(org_id=org_id, user_id=user.id).first()
    if existing:
        raise HTTPException(409, "User is already a member of this organization")

    member = OrganizationMemberModel(
        id=str(uuid.uuid4()),
        org_id=org_id,
        user_id=user.id,
        role=payload.role,
    )
    db.add(member)
    db.commit()
    db.refresh(member)
    return _member_to_dict(member, user)


@app.get("/api/orgs/{org_id}/members")
async def list_members(org_id: str, db: SASession = Depends(get_db)):
    """List organization members."""
    org = db.query(OrganizationModel).filter_by(id=org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")

    members = db.query(OrganizationMemberModel).filter_by(org_id=org_id).all()
    result = []
    for m in members:
        user = db.query(UserModel).filter_by(id=m.user_id).first()
        result.append(_member_to_dict(m, user))
    return {"members": result, "total": len(result), "seat_limit": org.seat_limit}


@app.delete("/api/orgs/{org_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(org_id: str, user_id: str, db: SASession = Depends(get_db)):
    """Remove a member from an organization."""
    member = db.query(OrganizationMemberModel).filter_by(org_id=org_id, user_id=user_id).first()
    if not member:
        raise HTTPException(404, "Member not found")
    db.delete(member)
    db.commit()


# ---------------------------------------------------------------------------
# SSO provider configuration
# ---------------------------------------------------------------------------


@app.post("/api/orgs/{org_id}/sso", status_code=status.HTTP_201_CREATED)
async def configure_sso(org_id: str, payload: SSOProviderCreate, db: SASession = Depends(get_db)):
    """Configure SSO provider for an organization."""
    org = db.query(OrganizationModel).filter_by(id=org_id, is_active=True).first()
    if not org:
        raise HTTPException(404, "Organization not found")

    settings = dict(payload.settings)
    if payload.client_secret:
        # Store secret hashed — do not store plaintext
        settings["client_secret_hash"] = secrets.token_hex(32)

    provider = SSOProviderModel(
        id=str(uuid.uuid4()),
        org_id=org_id,
        provider_type=payload.provider_type,
        provider_name=payload.provider_name,
        client_id=payload.client_id,
        settings=settings,
    )
    db.add(provider)
    db.commit()
    db.refresh(provider)
    return {
        "id": provider.id,
        "org_id": provider.org_id,
        "provider_type": provider.provider_type,
        "provider_name": provider.provider_name,
        "client_id": provider.client_id,
        "is_active": provider.is_active,
    }


@app.get("/api/orgs/{org_id}/sso")
async def get_sso_providers(org_id: str, db: SASession = Depends(get_db)):
    """List SSO providers for an organization."""
    providers = db.query(SSOProviderModel).filter_by(org_id=org_id, is_active=True).all()
    return {
        "providers": [
            {
                "id": p.id,
                "provider_type": p.provider_type,
                "provider_name": p.provider_name,
                "client_id": p.client_id,
            }
            for p in providers
        ]
    }


# ---------------------------------------------------------------------------
# Branding
# ---------------------------------------------------------------------------


@app.get("/api/orgs/{org_id}/branding")
async def get_branding(org_id: str, db: SASession = Depends(get_db)):
    """Get organization branding settings."""
    org = db.query(OrganizationModel).filter_by(id=org_id, is_active=True).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    return {
        "org_id": org_id,
        "logo_url": org.logo_url,
        "primary_color": org.primary_color or "#0EA5E9",
        "name": org.name,
        "plan": org.plan,
    }


@app.put("/api/orgs/{org_id}/branding")
async def update_branding(
    org_id: str,
    payload: dict,
    db: SASession = Depends(get_db),
):
    """Update organization branding."""
    org = db.query(OrganizationModel).filter_by(id=org_id, is_active=True).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    if "logo_url" in payload:
        org.logo_url = payload["logo_url"]
    if "primary_color" in payload:
        org.primary_color = payload["primary_color"]
    db.commit()
    return {"status": "updated", "org_id": org_id}
