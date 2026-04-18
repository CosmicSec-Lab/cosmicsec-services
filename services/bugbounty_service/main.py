"""Phase 5 Bug Bounty service — PostgreSQL-backed via SQLAlchemy."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from services.common.db import get_db
from services.common.models import BugBountyProgramModel, BugBountySubmissionModel

app = FastAPI(title="CosmicSec Bug Bounty Service", version="1.0.0")

platforms = ["hackerone", "bugcrowd", "intigriti", "yeswehack", "synack"]
report_templates: list[dict[str, Any]] = [
    {"template_id": "tmpl-web-xss", "name": "Web XSS Report", "category": "web"},
    {"template_id": "tmpl-api-authz", "name": "API Authorization Report", "category": "api"},
]


class ProgramCreate(BaseModel):
    platform: str
    program_name: str
    scope: list[str] = Field(default_factory=list)
    reward_model: str = "bounty"


class ReconRequest(BaseModel):
    program_id: str
    target: str


class PrioritizationRequest(BaseModel):
    findings: list[dict] = Field(default_factory=list)


class SubmissionCreate(BaseModel):
    program_id: str
    title: str
    description: str
    severity: str = "medium"
    poc: str | None = None


class SubmissionStatusUpdate(BaseModel):
    status: str = Field(..., description="draft | submitted | triaged | accepted | rejected | paid")
    reward_amount: int | None = Field(default=None, ge=0)


class CollaborationShare(BaseModel):
    program_id: str
    title: str
    message: str
    participants: list[str] = Field(default_factory=list)


# In-memory collaboration threads (non-critical, ephemeral)
_collaboration_threads: list[dict[str, Any]] = []

_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_ALLOWED_STATUS = {"draft", "submitted", "triaged", "accepted", "rejected", "paid"}
_STATUS_TRANSITIONS = {
    "draft": {"submitted", "rejected"},
    "submitted": {"triaged", "accepted", "rejected"},
    "triaged": {"accepted", "rejected"},
    "accepted": {"paid"},
    "rejected": set(),
    "paid": set(),
}


@app.get("/health")
def health() -> dict:
    return {
        "status": "healthy",
        "service": "bugbounty",
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/platforms")
def list_platforms() -> dict:
    return {"platforms": platforms, "total": len(platforms)}


@app.post("/programs", status_code=201)
def create_program(payload: ProgramCreate, db: Session = Depends(get_db)) -> dict:
    if payload.platform.lower() not in platforms:
        raise HTTPException(status_code=400, detail="Unsupported bug bounty platform")
    program_id = f"bbp-{uuid.uuid4().hex[:8]}"
    entry = BugBountyProgramModel(
        id=program_id,
        platform=payload.platform.lower(),
        program_name=payload.program_name,
        scope=payload.scope,
        reward_model=payload.reward_model,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return _program_to_dict(entry)


@app.get("/programs")
def list_programs(platform: str | None = None, db: Session = Depends(get_db)) -> dict:
    query = db.query(BugBountyProgramModel)
    if platform:
        query = query.filter(BugBountyProgramModel.platform == platform.lower())
    items = query.all()
    return {"items": [_program_to_dict(p) for p in items], "total": len(items)}


@app.post("/recon/auto")
def automated_recon(payload: ReconRequest, db: Session = Depends(get_db)) -> dict:
    program = (
        db.query(BugBountyProgramModel)
        .filter(BugBountyProgramModel.id == payload.program_id)
        .first()
    )
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    assets = [payload.target, f"api.{payload.target}", f"admin.{payload.target}"]
    return {
        "program_id": payload.program_id,
        "target": payload.target,
        "discovered_assets": assets,
        "summary": {"total_assets": len(assets)},
    }


@app.post("/findings/prioritize")
def prioritize_findings(payload: PrioritizationRequest) -> dict:
    ranked = sorted(payload.findings, key=lambda x: int(x.get("score", 0)), reverse=True)
    return {"ranked_findings": ranked, "total": len(ranked)}


@app.post("/poc/build")
def build_poc_template(finding: dict) -> dict:
    title = finding.get("title", "vulnerability")
    return {
        "title": title,
        "template": f"PoC for {title}\\n1. Setup\\n2. Steps to reproduce\\n3. Impact\\n4. Mitigation",
    }


@app.post("/submissions", status_code=201)
def create_submission(payload: SubmissionCreate, db: Session = Depends(get_db)) -> dict:
    program = (
        db.query(BugBountyProgramModel)
        .filter(BugBountyProgramModel.id == payload.program_id)
        .first()
    )
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    severity = payload.severity.lower().strip()
    if severity not in _ALLOWED_SEVERITIES:
        raise HTTPException(status_code=400, detail="Unsupported severity")
    submission_id = f"sub-{uuid.uuid4().hex[:10]}"
    entry = BugBountySubmissionModel(
        id=submission_id,
        program_id=payload.program_id,
        title=payload.title,
        description=payload.description,
        severity=severity,
        poc=payload.poc,
        status="draft",
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return _submission_to_dict(entry)


@app.post("/submissions/{submission_id}/submit")
def submit_submission(submission_id: str, db: Session = Depends(get_db)) -> dict:
    entry = (
        db.query(BugBountySubmissionModel)
        .filter(BugBountySubmissionModel.id == submission_id)
        .first()
    )
    if not entry:
        raise HTTPException(status_code=404, detail="Submission not found")
    if entry.status != "draft":
        raise HTTPException(status_code=400, detail="Only draft submissions can be submitted")
    entry.status = "submitted"
    entry.submitted_at = datetime.now(UTC)
    db.commit()
    db.refresh(entry)
    return _submission_to_dict(entry)


@app.get("/submissions")
def list_submissions(
    status: str | None = None,
    program_id: str | None = None,
    severity: str | None = None,
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> dict:
    query = db.query(BugBountySubmissionModel)

    if status:
        normalized_status = status.lower().strip()
        if normalized_status not in _ALLOWED_STATUS:
            raise HTTPException(status_code=400, detail="Unsupported status filter")
        query = query.filter(BugBountySubmissionModel.status == normalized_status)

    if program_id:
        query = query.filter(BugBountySubmissionModel.program_id == program_id)

    if severity:
        normalized_severity = severity.lower().strip()
        if normalized_severity not in _ALLOWED_SEVERITIES:
            raise HTTPException(status_code=400, detail="Unsupported severity filter")
        query = query.filter(BugBountySubmissionModel.severity == normalized_severity)

    total = query.count()
    rows = (
        query.order_by(BugBountySubmissionModel.created_at.desc()).offset(offset).limit(limit).all()
    )
    return {
        "items": [_submission_to_dict(s) for s in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@app.get("/submissions/{submission_id}")
def get_submission(submission_id: str, db: Session = Depends(get_db)) -> dict:
    entry = (
        db.query(BugBountySubmissionModel)
        .filter(BugBountySubmissionModel.id == submission_id)
        .first()
    )
    if not entry:
        raise HTTPException(status_code=404, detail="Submission not found")
    return _submission_to_dict(entry)


@app.patch("/submissions/{submission_id}/status")
def update_submission_status(
    submission_id: str,
    payload: SubmissionStatusUpdate,
    db: Session = Depends(get_db),
) -> dict:
    entry = (
        db.query(BugBountySubmissionModel)
        .filter(BugBountySubmissionModel.id == submission_id)
        .first()
    )
    if not entry:
        raise HTTPException(status_code=404, detail="Submission not found")

    next_status = payload.status.lower().strip()
    if next_status not in _ALLOWED_STATUS:
        raise HTTPException(status_code=400, detail="Unsupported status")

    allowed = _STATUS_TRANSITIONS.get(entry.status, set())
    if next_status not in allowed and next_status != entry.status:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status transition: {entry.status} -> {next_status}",
        )

    entry.status = next_status
    if next_status == "submitted" and entry.submitted_at is None:
        entry.submitted_at = datetime.now(UTC)

    if payload.reward_amount is not None:
        if next_status != "paid":
            raise HTTPException(status_code=400, detail="reward_amount is only valid for paid status")
        entry.reward_amount = payload.reward_amount

    db.commit()
    db.refresh(entry)
    return _submission_to_dict(entry)


@app.get("/dashboard/earnings")
def earnings_dashboard(db: Session = Depends(get_db)) -> dict:
    all_subs = db.query(BugBountySubmissionModel).all()
    paid = [s for s in all_subs if s.status == "paid"]
    total_paid = sum(s.reward_amount for s in paid)
    pending_review = len([s for s in all_subs if s.status in {"submitted", "triaged"}])
    avg_payout = (total_paid / len(paid)) if paid else 0
    return {
        "total_submissions": len(all_subs),
        "paid_submissions": len(paid),
        "total_paid": total_paid,
        "pending_review": pending_review,
        "average_payout": round(avg_payout, 2),
    }


@app.get("/dashboard/status-breakdown")
def submission_status_breakdown(db: Session = Depends(get_db)) -> dict:
    all_subs = db.query(BugBountySubmissionModel).all()
    breakdown = {status: 0 for status in sorted(_ALLOWED_STATUS)}
    for sub in all_subs:
        breakdown[sub.status] = breakdown.get(sub.status, 0) + 1
    return {"breakdown": breakdown, "total": len(all_subs)}


@app.get("/timeline")
def timeline(program_id: str | None = None, db: Session = Depends(get_db)) -> dict:
    events = []
    programs_q = db.query(BugBountyProgramModel)
    if program_id:
        programs_q = programs_q.filter(BugBountyProgramModel.id == program_id)
    for program in programs_q.all():
        events.append(
            {
                "event": "program_created",
                "program_id": program.id,
                "at": program.created_at.isoformat() if program.created_at else None,
            }
        )
    subs_q = db.query(BugBountySubmissionModel)
    if program_id:
        subs_q = subs_q.filter(BugBountySubmissionModel.program_id == program_id)
    for sub in subs_q.all():
        events.append(
            {
                "event": "submission_status",
                "submission_id": sub.id,
                "status": sub.status,
            }
        )
    return {"events": events, "total": len(events)}


@app.post("/collaboration/share")
def collaboration_share(payload: CollaborationShare) -> dict:
    entry = {
        "thread_id": f"thread-{uuid.uuid4().hex[:8]}",
        "program_id": payload.program_id,
        "title": payload.title,
        "message": payload.message,
        "participants": payload.participants,
        "created_at": datetime.now(UTC).isoformat(),
    }
    _collaboration_threads.append(entry)
    return entry


@app.get("/collaboration/threads")
def collaboration_threads_list(program_id: str | None = None) -> dict:
    items = _collaboration_threads
    if program_id:
        items = [t for t in items if t["program_id"] == program_id]
    return {"items": items, "total": len(items)}


@app.get("/reports/templates")
def list_report_templates() -> dict:
    return {"templates": report_templates, "total": len(report_templates)}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _program_to_dict(p: BugBountyProgramModel) -> dict:
    return {
        "program_id": p.id,
        "platform": p.platform,
        "program_name": p.program_name,
        "scope": p.scope,
        "reward_model": p.reward_model,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    }


def _submission_to_dict(s: BugBountySubmissionModel) -> dict:
    return {
        "submission_id": s.id,
        "program_id": s.program_id,
        "title": s.title,
        "description": s.description,
        "severity": s.severity,
        "poc": s.poc,
        "status": s.status,
        "reward_amount": s.reward_amount,
        "submitted_at": s.submitted_at.isoformat() if s.submitted_at else None,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }
