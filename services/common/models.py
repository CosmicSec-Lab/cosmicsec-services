"""Core ORM models for all CosmicSec service entities."""

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)

from .db import Base

# ---------------------------------------------------------------------------
# Auth / Users
# ---------------------------------------------------------------------------


class UserModel(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    email = Column(String, unique=True, nullable=False, index=True)
    full_name = Column(String, nullable=False)
    hashed_password = Column("password_hash", String, nullable=True)
    role = Column(String, nullable=False, default="user")
    is_active = Column(Boolean, nullable=False, default=True)
    totp_secret = Column(String, nullable=True)
    totp_enabled = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class SessionModel(Base):
    __tablename__ = "sessions"

    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String, nullable=False, unique=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class APIKeyModel(Base):
    __tablename__ = "api_keys"

    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    key_hash = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False, default="default")
    scopes = Column(JSON, nullable=False, default=list)
    is_active = Column(Boolean, nullable=False, default=True)
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String, nullable=False, index=True)
    resource = Column(String, nullable=True)
    resource_id = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    extra = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_audit_logs_created_at", "created_at"),)


# ---------------------------------------------------------------------------
# Scans & Findings
# ---------------------------------------------------------------------------


class ScanModel(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    target = Column(String, nullable=False, index=True)
    scan_types = Column(JSON, nullable=True)
    tool = Column(String, nullable=True)
    status = Column(String, nullable=False, default="pending", index=True)
    progress = Column(Integer, nullable=False, default=0)
    source = Column(String, nullable=False, default="web_scan")
    raw_output = Column(Text, nullable=True)
    summary = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)


class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="info", index=True)
    description = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    tool = Column(String, nullable=True)
    target = Column(String, nullable=True, index=True)
    cve_id = Column(String, nullable=True, index=True)
    cvss_score = Column(Float, nullable=True)
    mitre_technique = Column(String, nullable=True)
    source = Column(String, nullable=False, default="web_scan")
    extra = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_findings_severity_created", "severity", "created_at"),)


# ---------------------------------------------------------------------------
# CLI Agent Sessions
# ---------------------------------------------------------------------------


class AgentSessionModel(Base):
    __tablename__ = "agent_sessions"

    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    manifest = Column(JSON, nullable=False, default=dict)
    status = Column(String, nullable=False, default="connected")
    last_seen_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AgentTaskModel(Base):
    __tablename__ = "agent_tasks"

    id = Column(String, primary_key=True)
    agent_id = Column(
        String,
        ForeignKey("agent_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    requested_by = Column(String, nullable=True, index=True)
    tool = Column(String, nullable=False)
    target = Column(String, nullable=True)
    args = Column(JSON, nullable=False, default=list)
    task_metadata = Column(JSON, nullable=False, default=dict)
    status = Column(String, nullable=False, default="dispatched", index=True)
    progress = Column(Integer, nullable=False, default=0)
    message = Column(Text, nullable=True)
    reason = Column(Text, nullable=True)
    result = Column(JSON, nullable=True)
    created_at = Column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        Index("ix_agent_tasks_agent_status", "agent_id", "status"),
        Index("ix_agent_tasks_agent_created", "agent_id", "created_at"),
    )


# ---------------------------------------------------------------------------
# Bug Bounty
# ---------------------------------------------------------------------------


class BugBountyProgramModel(Base):
    __tablename__ = "bugbounty_programs"

    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    platform = Column(String, nullable=False, index=True)
    program_name = Column(String, nullable=False)
    scope = Column(JSON, nullable=False, default=list)
    reward_model = Column(String, nullable=False, default="bounty")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class BugBountySubmissionModel(Base):
    __tablename__ = "bugbounty_submissions"

    id = Column(String, primary_key=True)
    program_id = Column(
        String, ForeignKey("bugbounty_programs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=False, default="medium")
    poc = Column(Text, nullable=True)
    status = Column(String, nullable=False, default="draft", index=True)
    reward_amount = Column(Integer, nullable=False, default=0)
    submitted_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class BugBountyThreadModel(Base):
    __tablename__ = "bugbounty_threads"

    id = Column(String, primary_key=True)
    program_id = Column(
        String, ForeignKey("bugbounty_programs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    participants = Column(JSON, nullable=False, default=list)
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_bugbounty_threads_program_created", "program_id", "created_at"),)


class BugBountyActivityModel(Base):
    __tablename__ = "bugbounty_activity"

    id = Column(String, primary_key=True)
    program_id = Column(
        String, ForeignKey("bugbounty_programs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    submission_id = Column(
        String,
        ForeignKey("bugbounty_submissions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    activity_type = Column(String, nullable=False, index=True)
    actor = Column(String, nullable=True, index=True)
    detail = Column(Text, nullable=True)
    extra_metadata = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_bugbounty_activity_program_created", "program_id", "created_at"),
        Index("ix_bugbounty_activity_submission_created", "submission_id", "created_at"),
    )


# ---------------------------------------------------------------------------
# Collaboration
# ---------------------------------------------------------------------------


class CollabMessageModel(Base):
    __tablename__ = "collab_messages"

    id = Column(String, primary_key=True)
    room_id = Column(String, nullable=False, index=True)
    username = Column(String, nullable=False)
    text = Column(Text, nullable=False)
    mentions = Column(JSON, nullable=False, default=list)
    thread_id = Column(String, nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_collab_messages_room_created", "room_id", "created_at"),)


class CollabReportSectionModel(Base):
    __tablename__ = "collab_report_sections"

    id = Column(String, primary_key=True)
    room_id = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    author = Column(String, nullable=False)
    section_type = Column(String, nullable=False, default="finding")
    revision = Column(Integer, nullable=False, default=1)
    edit_history = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


# ---------------------------------------------------------------------------
# Integration Service
# ---------------------------------------------------------------------------


class IntegrationConfigModel(Base):
    __tablename__ = "integration_configs"

    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    integration_type = Column(String, nullable=False, index=True)
    name = Column(String, nullable=False)
    config = Column(JSON, nullable=False, default=dict)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


# ---------------------------------------------------------------------------
# Phase 5 — SOC / IR
# ---------------------------------------------------------------------------


class Phase5AlertModel(Base):
    __tablename__ = "phase5_alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="info", index=True)
    title = Column(String, nullable=False)
    payload = Column(JSON, nullable=False, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_phase5_alerts_severity_created", "severity", "created_at"),)


class Phase5IncidentModel(Base):
    __tablename__ = "phase5_incidents"

    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="medium", index=True)
    status = Column(String, nullable=False, default="open", index=True)
    evidence = Column(JSON, nullable=False, default=list)
    timeline = Column(JSON, nullable=False, default=list)
    assigned_to = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class Phase5PolicyModel(Base):
    __tablename__ = "phase5_policies"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    policy_type = Column(String, nullable=False, default="access")
    rules = Column(JSON, nullable=False, default=list)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Phase5IOCModel(Base):
    __tablename__ = "phase5_iocs"

    id = Column(String, primary_key=True)
    ioc_type = Column(String, nullable=False, index=True)
    value = Column(String, nullable=False, index=True)
    source = Column(String, nullable=True)
    confidence = Column(Float, nullable=False, default=0.5)
    tags = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


# ---------------------------------------------------------------------------
# Plugin Marketplace (Phase L)
# ---------------------------------------------------------------------------


class PluginMarketplaceModel(Base):
    __tablename__ = "plugin_marketplace"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False, unique=True, index=True)
    version = Column(String, nullable=False, default="0.0.0")
    description = Column(Text, nullable=True)
    author = Column(String, nullable=True)
    tags = Column(JSON, nullable=False, default=list)
    download_url = Column(String, nullable=True)
    checksum_sha256 = Column(String, nullable=True)
    downloads = Column(Integer, nullable=False, default=0)
    source_repo = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class PluginRatingModel(Base):
    __tablename__ = "plugin_ratings"

    id = Column(String, primary_key=True)
    plugin_id = Column(String, nullable=False, index=True)
    user_id = Column(String, nullable=False)
    rating = Column(Integer, nullable=False)
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_plugin_ratings_plugin_user", "plugin_id", "user_id"),)


class PluginRepositoryModel(Base):
    __tablename__ = "plugin_repositories"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    index_url = Column(String, nullable=False)
    trust_level = Column(String, nullable=False, default="community")
    enabled = Column(Boolean, nullable=False, default=True)
    last_sync = Column(DateTime(timezone=True), nullable=True)
    imported_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


# ---------------------------------------------------------------------------
# Integration Event Log (Phase L)
# ---------------------------------------------------------------------------


class IntegrationEventModel(Base):
    __tablename__ = "integration_events"

    id = Column(String, primary_key=True)
    provider = Column(String, nullable=False, index=True)
    event_type = Column(String, nullable=False, index=True)
    payload = Column(JSON, nullable=False, default=dict)
    status = Column(String, nullable=False, default="stored")
    response_code = Column(Integer, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_integration_events_provider_created", "provider", "created_at"),)


# ---------------------------------------------------------------------------
# Organizations (Phase R — Multi-tenancy)
# ---------------------------------------------------------------------------


class OrganizationModel(Base):
    __tablename__ = "organizations"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    slug = Column(String, nullable=False, unique=True, index=True)
    logo_url = Column(String, nullable=True)
    primary_color = Column(String, nullable=True, default="#0EA5E9")
    seat_limit = Column(Integer, nullable=False, default=5)
    plan = Column(String, nullable=False, default="free")  # free|pro|enterprise
    settings = Column(JSON, nullable=False, default=dict)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class OrganizationMemberModel(Base):
    __tablename__ = "organization_members"

    id = Column(String, primary_key=True)
    org_id = Column(
        String, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String, nullable=False, default="member")  # owner|admin|member|viewer
    invited_by = Column(String, nullable=True)
    joined_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (Index("ix_org_members_org_user", "org_id", "user_id"),)


class SSOProviderModel(Base):
    __tablename__ = "sso_providers"

    id = Column(String, primary_key=True)
    org_id = Column(
        String, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_type = Column(String, nullable=False)  # oidc|saml
    provider_name = Column(String, nullable=False)  # okta|azure|google|github
    client_id = Column(String, nullable=True)
    # client_secret is stored encrypted in settings JSONB
    settings = Column(JSON, nullable=False, default=dict)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
