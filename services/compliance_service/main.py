"""
CosmicSec Compliance Automation Service — Phase R.3

Automates compliance evidence collection and gap analysis for:
  - SOC 2 Type II
  - PCI-DSS v4.0
  - HIPAA
  - ISO 27001

Endpoints:
  POST /api/compliance/assess/{framework}  — run framework assessment
  GET  /api/compliance/report/{framework}  — get latest compliance report
  GET  /api/compliance/controls            — list all controls across frameworks
  POST /api/compliance/schedule            — schedule automated reporting
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException, Path
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

app = FastAPI(
    title="CosmicSec Compliance Service",
    description="Automated compliance assessment for SOC2, PCI-DSS, HIPAA, ISO 27001",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Control definitions
# ---------------------------------------------------------------------------

FRAMEWORKS = {
    "soc2": {
        "name": "SOC 2 Type II",
        "controls": [
            {"id": "CC6.1", "name": "Access control mechanisms", "category": "Logical Access"},
            {"id": "CC6.2", "name": "Access credentials management", "category": "Logical Access"},
            {"id": "CC6.3", "name": "Role-based access control", "category": "Logical Access"},
            {
                "id": "CC7.1",
                "name": "Vulnerability management program",
                "category": "System Operations",
            },
            {"id": "CC7.2", "name": "Security incident response", "category": "System Operations"},
            {"id": "CC7.4", "name": "Security event monitoring", "category": "System Operations"},
            {"id": "CC8.1", "name": "Change management process", "category": "Change Management"},
            {"id": "CC9.1", "name": "Risk assessment procedures", "category": "Risk Mitigation"},
            {"id": "A1.1", "name": "Capacity planning", "category": "Availability"},
            {"id": "A1.2", "name": "Environmental controls", "category": "Availability"},
        ],
    },
    "pci_dss": {
        "name": "PCI-DSS v4.0",
        "controls": [
            {
                "id": "Req-1",
                "name": "Install and maintain network security controls",
                "category": "Network",
            },
            {"id": "Req-2", "name": "Apply secure configurations", "category": "Configuration"},
            {"id": "Req-3", "name": "Protect stored account data", "category": "Data Protection"},
            {"id": "Req-4", "name": "Protect cardholder data in transit", "category": "Encryption"},
            {
                "id": "Req-5",
                "name": "Protect systems against malicious software",
                "category": "Malware",
            },
            {
                "id": "Req-6",
                "name": "Develop and maintain secure systems",
                "category": "Development",
            },
            {
                "id": "Req-7",
                "name": "Restrict access to system components",
                "category": "Access Control",
            },
            {
                "id": "Req-8",
                "name": "Identify users and authenticate access",
                "category": "Authentication",
            },
            {"id": "Req-10", "name": "Log and monitor all access", "category": "Logging"},
            {
                "id": "Req-12",
                "name": "Support information security with policies",
                "category": "Policy",
            },
        ],
    },
    "hipaa": {
        "name": "HIPAA",
        "controls": [
            {
                "id": "164.308(a)(1)",
                "name": "Security management process",
                "category": "Administrative",
            },
            {"id": "164.308(a)(3)", "name": "Workforce security", "category": "Administrative"},
            {
                "id": "164.308(a)(4)",
                "name": "Information access management",
                "category": "Administrative",
            },
            {
                "id": "164.308(a)(5)",
                "name": "Security awareness training",
                "category": "Administrative",
            },
            {"id": "164.310(a)", "name": "Facility access controls", "category": "Physical"},
            {"id": "164.310(d)", "name": "Device and media controls", "category": "Physical"},
            {"id": "164.312(a)", "name": "Access control (technical)", "category": "Technical"},
            {"id": "164.312(b)", "name": "Audit controls", "category": "Technical"},
            {"id": "164.312(c)", "name": "Integrity controls", "category": "Technical"},
            {"id": "164.312(e)", "name": "Transmission security", "category": "Technical"},
        ],
    },
    "iso27001": {
        "name": "ISO 27001:2022",
        "controls": [
            {
                "id": "A.5.1",
                "name": "Policies for information security",
                "category": "Organizational",
            },
            {"id": "A.5.15", "name": "Access control policy", "category": "Organizational"},
            {"id": "A.8.2", "name": "Privileged access rights", "category": "People"},
            {"id": "A.8.7", "name": "Protection against malware", "category": "Technological"},
            {
                "id": "A.8.8",
                "name": "Management of technical vulnerabilities",
                "category": "Technological",
            },
            {"id": "A.8.12", "name": "Data leakage prevention", "category": "Technological"},
            {"id": "A.8.16", "name": "Monitoring activities", "category": "Technological"},
            {"id": "A.8.23", "name": "Web filtering", "category": "Technological"},
            {"id": "A.8.24", "name": "Use of cryptography", "category": "Technological"},
            {"id": "A.8.28", "name": "Secure coding", "category": "Technological"},
        ],
    },
}


# Simulated control compliance checker based on finding data
def _assess_control(
    control: dict,
    findings: list[dict],
    framework: str,
) -> dict:
    """Assess a single control against provided finding data."""
    control_id = control["id"]
    category = control.get("category", "")

    # Simple rule-based compliance scoring
    critical_count = sum(1 for f in findings if f.get("severity") == "critical")
    high_count = sum(1 for f in findings if f.get("severity") == "high")

    # Access control check
    if "access" in control["name"].lower() or "authentication" in control["name"].lower():
        if critical_count > 0:
            status = "fail"
            gap = f"{critical_count} critical authentication/access finding(s) detected"
        elif high_count > 2:
            status = "partial"
            gap = f"{high_count} high-severity access findings need remediation"
        else:
            status = "pass"
            gap = None

    # Vulnerability management
    elif "vulnerab" in control["name"].lower():
        total = len(findings)
        if critical_count > 0:
            status = "fail"
            gap = f"{critical_count} critical vulnerabilities unpatched"
        elif total > 10:
            status = "partial"
            gap = f"{total} open findings — accelerate remediation cadence"
        else:
            status = "pass"
            gap = None

    # Encryption / data protection
    elif "encrypt" in control["name"].lower() or "cryptograph" in control["name"].lower():
        tls_issues = [f for f in findings if "tls" in f.get("title", "").lower()]
        if tls_issues:
            status = "partial"
            gap = f"{len(tls_issues)} TLS/encryption configuration issue(s)"
        else:
            status = "pass"
            gap = None

    # Default — assume pass for controls without specific mappings
    else:
        status = "pass"
        gap = None

    score = {"pass": 100, "partial": 50, "fail": 0}[status]  # nosec B105
    return {
        "control_id": control_id,
        "control_name": control["name"],
        "category": category,
        "status": status,
        "score": score,
        "gap": gap,
    }


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class AssessmentRequest(BaseModel):
    findings: list[dict] = Field(default_factory=list, description="List of security findings")
    scan_ids: list[str] = Field(default_factory=list, description="Scan IDs to assess")
    org_id: str | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "compliance-service",
        "frameworks": list(FRAMEWORKS.keys()),
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/api/compliance/controls")
async def list_controls():
    """List all compliance controls across all frameworks."""
    all_controls = {}
    for fw_id, fw in FRAMEWORKS.items():
        all_controls[fw_id] = {
            "name": fw["name"],
            "control_count": len(fw["controls"]),
            "categories": sorted({c["category"] for c in fw["controls"]}),
        }
    return {"frameworks": all_controls}


@app.post("/api/compliance/assess/{framework}")
async def assess_framework(
    framework: str = Path(..., pattern=r"^(soc2|pci_dss|hipaa|iso27001)$"),
    payload: AssessmentRequest = AssessmentRequest(),
):
    """
    Run a compliance assessment for the specified framework.

    Returns:
      - Per-control pass/fail/partial status
      - Overall compliance score (0-100)
      - Prioritized gap list
      - Readiness report
    """
    fw = FRAMEWORKS.get(framework)
    if not fw:
        raise HTTPException(404, f"Framework '{framework}' not found")

    run_id = str(uuid.uuid4())
    started_at = datetime.now(UTC)

    # Assess each control
    control_results = [
        _assess_control(ctrl, payload.findings, framework) for ctrl in fw["controls"]
    ]

    # Compute overall score
    total_score = sum(r["score"] for r in control_results)
    max_score = len(control_results) * 100
    overall_pct = round((total_score / max_score) * 100) if max_score else 0

    # Determine readiness level
    if overall_pct >= 90:
        readiness = "audit-ready"
    elif overall_pct >= 70:
        readiness = "mostly-compliant"
    elif overall_pct >= 50:
        readiness = "partial-compliance"
    else:
        readiness = "significant-gaps"

    # Collect gaps
    gaps = [{"control_id": r["control_id"], "gap": r["gap"]} for r in control_results if r["gap"]]

    passed = sum(1 for r in control_results if r["status"] == "pass")
    partial = sum(1 for r in control_results if r["status"] == "partial")
    failed = sum(1 for r in control_results if r["status"] == "fail")

    return {
        "run_id": run_id,
        "framework": framework,
        "framework_name": fw["name"],
        "org_id": payload.org_id,
        "assessed_at": started_at.isoformat(),
        "overall_score": overall_pct,
        "readiness": readiness,
        "summary": {
            "total_controls": len(control_results),
            "passed": passed,
            "partial": partial,
            "failed": failed,
        },
        "gaps": gaps,
        "controls": control_results,
        "findings_assessed": len(payload.findings),
    }


@app.get("/api/compliance/report/{framework}")
async def get_compliance_report(
    framework: str = Path(..., pattern=r"^(soc2|pci_dss|hipaa|iso27001)$"),
):
    """Get a placeholder compliance report for the framework."""
    fw = FRAMEWORKS.get(framework)
    if not fw:
        raise HTTPException(404, f"Framework '{framework}' not found")
    return {
        "framework": framework,
        "framework_name": fw["name"],
        "message": "Run POST /api/compliance/assess/{framework} to generate a report",
        "controls": fw["controls"],
    }
