"""Phase 5 Bug Bounty service foundation."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="CosmicSec Bug Bounty Service", version="1.0.0")

platforms = ["hackerone", "bugcrowd", "intigriti", "yeswehack", "synack"]
programs: Dict[str, Dict[str, Any]] = {}
submissions: Dict[str, Dict[str, Any]] = {}
collaboration_threads: List[Dict[str, Any]] = []
report_templates: List[Dict[str, Any]] = [
    {"template_id": "tmpl-web-xss", "name": "Web XSS Report", "category": "web"},
    {"template_id": "tmpl-api-authz", "name": "API Authorization Report", "category": "api"},
]


class ProgramCreate(BaseModel):
    platform: str
    program_name: str
    scope: List[str] = Field(default_factory=list)
    reward_model: str = "bounty"


class ReconRequest(BaseModel):
    program_id: str
    target: str


class PrioritizationRequest(BaseModel):
    findings: List[dict] = Field(default_factory=list)


class SubmissionCreate(BaseModel):
    program_id: str
    title: str
    description: str
    severity: str = "medium"
    poc: Optional[str] = None


class CollaborationShare(BaseModel):
    program_id: str
    title: str
    message: str
    participants: List[str] = Field(default_factory=list)


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": "bugbounty", "timestamp": datetime.utcnow().isoformat()}


@app.get("/platforms")
def list_platforms() -> dict:
    return {"platforms": platforms, "total": len(platforms)}


@app.post("/programs", status_code=201)
def create_program(payload: ProgramCreate) -> dict:
    if payload.platform.lower() not in platforms:
        raise HTTPException(status_code=400, detail="Unsupported bug bounty platform")
    program_id = f"bbp-{len(programs) + 1:04d}"
    entry = {
        "program_id": program_id,
        "platform": payload.platform.lower(),
        "program_name": payload.program_name,
        "scope": payload.scope,
        "reward_model": payload.reward_model,
        "created_at": datetime.utcnow().isoformat(),
    }
    programs[program_id] = entry
    return entry


@app.get("/programs")
def list_programs(platform: Optional[str] = None) -> dict:
    items = list(programs.values())
    if platform:
        items = [p for p in items if p["platform"] == platform.lower()]
    return {"items": items, "total": len(items)}


@app.post("/recon/auto")
def automated_recon(payload: ReconRequest) -> dict:
    if payload.program_id not in programs:
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
def create_submission(payload: SubmissionCreate) -> dict:
    if payload.program_id not in programs:
        raise HTTPException(status_code=404, detail="Program not found")
    submission_id = f"sub-{len(submissions) + 1:05d}"
    entry = {
        "submission_id": submission_id,
        "program_id": payload.program_id,
        "title": payload.title,
        "description": payload.description,
        "severity": payload.severity,
        "poc": payload.poc,
        "status": "draft",
        "created_at": datetime.utcnow().isoformat(),
    }
    submissions[submission_id] = entry
    return entry


@app.post("/submissions/{submission_id}/submit")
def submit_submission(submission_id: str) -> dict:
    entry = submissions.get(submission_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Submission not found")
    entry["status"] = "submitted"
    entry["submitted_at"] = datetime.utcnow().isoformat()
    return entry


@app.get("/dashboard/earnings")
def earnings_dashboard() -> dict:
    paid = [s for s in submissions.values() if s.get("status") == "paid"]
    total_paid = sum(int(s.get("reward_amount", 0)) for s in paid)
    return {
        "total_submissions": len(submissions),
        "paid_submissions": len(paid),
        "total_paid": total_paid,
    }


@app.get("/timeline")
def timeline(program_id: Optional[str] = None) -> dict:
    events = []
    for program in programs.values():
        if program_id and program["program_id"] != program_id:
            continue
        events.append({"event": "program_created", "program_id": program["program_id"], "at": program["created_at"]})
    for sub in submissions.values():
        if program_id and sub["program_id"] != program_id:
            continue
        events.append({"event": "submission_status", "submission_id": sub["submission_id"], "status": sub["status"]})
    return {"events": events, "total": len(events)}


@app.post("/collaboration/share")
def collaboration_share(payload: CollaborationShare) -> dict:
    entry = {
        "thread_id": f"thread-{len(collaboration_threads)+1:04d}",
        "program_id": payload.program_id,
        "title": payload.title,
        "message": payload.message,
        "participants": payload.participants,
        "created_at": datetime.utcnow().isoformat(),
    }
    collaboration_threads.append(entry)
    return entry


@app.get("/collaboration/threads")
def collaboration_threads_list(program_id: Optional[str] = None) -> dict:
    items = collaboration_threads
    if program_id:
        items = [t for t in items if t["program_id"] == program_id]
    return {"items": items, "total": len(items)}


@app.get("/reports/templates")
def list_report_templates() -> dict:
    return {"templates": report_templates, "total": len(report_templates)}
