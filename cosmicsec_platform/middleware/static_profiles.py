"""Static continuity response profiles for hybrid runtime fallback paths."""

from __future__ import annotations

import time
from typing import Any

from fastapi import Request

StaticProfile = dict[str, Any]


def auth_login_profile(_: Request, payload: dict[str, Any] | None) -> StaticProfile:
    email = (payload or {}).get("email", "demo@cosmicsec.local")
    return {
        "status": "preview_auth",
        "access_token": "demo-preview-token",  # nosec B105
        "refresh_token": "demo-preview-refresh-token",  # nosec B105
        "token_type": "bearer",  # nosec B105
        "expires_in": 1800,
        "preview_user": {"email": email, "role": "demo_viewer"},
        "next_action": "Use demo mode for preview auth or recover auth service for full login.",
    }


def scan_create_profile(_: Request, payload: dict[str, Any] | None) -> StaticProfile:
    return {
        "id": f"fallback-{int(time.time())}",
        "target": (payload or {}).get("target", "unknown"),
        "status": "queued_fallback",
        "message": "Static disaster-control scan queue accepted request for continuity.",
        "next_action": "Track queue and re-run full scan when dynamic services recover.",
        "runbook": "SOC-DR-SCAN-001",
    }


def scan_get_profile(_: Request, payload: dict[str, Any] | None) -> StaticProfile:
    return {
        "id": (payload or {}).get("scan_id", "unknown"),
        "status": "degraded_unavailable",
        "message": "Scan details unavailable in degraded mode.",
        "next_action": "Retry once scan service is restored.",
        "runbook": "SOC-DR-SCAN-002",
    }


def recon_lookup_profile(_: Request, payload: dict[str, Any] | None) -> StaticProfile:
    target = (payload or {}).get("target", "unknown")
    return {
        "target": target,
        "timestamp": time.time(),
        "findings": [
            {
                "source": "static",
                "summary": "Dynamic recon unavailable. Returned fallback preview only.",
            }
        ],
        "advisory": "Run full recon once dynamic services recover.",
        "runbook": "SOC-DR-RECON-001",
    }


def ai_health_profile(_: Request, __: dict[str, Any] | None) -> StaticProfile:
    return {
        "status": "degraded",
        "service": "ai-service",
        "capabilities": {"dynamic_inference": False, "fallback_profiles": True},
        "next_action": "Use deterministic static guidance until AI service recovers.",
        "runbook": "SOC-DR-AI-001",
    }


def report_generate_profile(_: Request, payload: dict[str, Any] | None) -> StaticProfile:
    return {
        "report_id": f"fallback-report-{int(time.time())}",
        "status": "queued_fallback",
        "format": (payload or {}).get("format", "json"),
        "message": "Report request accepted in degraded mode with delayed generation.",
        "next_action": "Regenerate once report service is restored.",
        "runbook": "SOC-DR-REPORT-001",
    }


def ai_analyze_profile(_: Request, payload: dict[str, Any] | None) -> StaticProfile:
    return {
        "analysis_id": f"demo-analysis-{int(time.time())}",
        "status": "complete",
        "risk_score": 72,
        "risk_level": "high",
        "summary": (
            "Demo analysis detected elevated attack surface with several exploitable "
            "vectors. Immediate remediation recommended for critical findings."
        ),
        "mitre_mappings": [
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            },
            {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": "Execution",
            },
            {"technique_id": "T1078", "technique_name": "Valid Accounts", "tactic": "Persistence"},
            {
                "technique_id": "T1083",
                "technique_name": "File and Directory Discovery",
                "tactic": "Discovery",
            },
        ],
        "recommendations": [
            "Patch CVE-2024-1234 on web application server immediately.",
            "Enforce MFA for all administrative accounts.",
            "Review and restrict outbound firewall rules.",
            "Rotate exposed API keys detected in scan findings.",
            "Enable WAF rules for SQL injection and XSS vectors.",
        ],
        "confidence": 0.87,
        "runbook": "SOC-AI-ANALYZE-001",
    }


def ai_correlate_profile(_: Request, payload: dict[str, Any] | None) -> StaticProfile:
    return {
        "correlation_id": f"demo-correlation-{int(time.time())}",
        "status": "complete",
        "clusters": [
            {
                "cluster_id": "C-001",
                "label": "Web Application Attack Chain",
                "findings": ["SQL Injection", "Auth Bypass", "Data Exfiltration"],
                "severity": "critical",
                "probability": 0.91,
            },
            {
                "cluster_id": "C-002",
                "label": "Misconfiguration Group",
                "findings": ["Open S3 Bucket", "Default Credentials", "Exposed Admin Panel"],
                "severity": "high",
                "probability": 0.78,
            },
        ],
        "total_findings_correlated": 14,
        "attack_paths": 3,
        "runbook": "SOC-AI-CORRELATE-001",
    }


def recon_dns_profile(_: Request, payload: dict[str, Any] | None) -> StaticProfile:
    target = (payload or {}).get("target", "example.com")
    return {
        "target": target,
        "timestamp": time.time(),
        "records": {
            "A": ["93.184.216.34"],
            "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
            "MX": ["0 example.com."],
            "NS": ["a.iana-servers.net.", "b.iana-servers.net."],
            "TXT": ["v=spf1 -all", "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
            "CNAME": [],
        },
        "subdomains": ["www", "mail", "api", "cdn", "dev"],
        "zone_transfer": False,
        "dnssec": True,
        "runbook": "SOC-DR-RECON-DNS-001",
    }


def collab_rooms_profile(_: Request, payload: dict[str, Any] | None) -> StaticProfile:
    return {
        "rooms": [
            {
                "id": "room-001",
                "name": "Incident Response — P1",
                "participants": ["analyst@demo.local", "admin@demo.local"],
                "created_at": "2024-01-15T10:00:00Z",
                "status": "active",
                "message_count": 47,
            },
            {
                "id": "room-002",
                "name": "Red Team Ops — Q1",
                "participants": ["redteam@demo.local"],
                "created_at": "2024-01-14T08:30:00Z",
                "status": "active",
                "message_count": 12,
            },
        ],
        "total": 2,
        "runbook": "SOC-COLLAB-ROOMS-001",
    }


def bugbounty_programs_profile(_: Request, payload: dict[str, Any] | None) -> StaticProfile:
    return {
        "programs": [
            {
                "id": "bb-001",
                "name": "AcmeCorp VDP",
                "platform": "HackerOne",
                "scope": ["*.acme.com", "api.acme.com"],
                "max_payout": 10000,
                "status": "active",
                "findings_submitted": 3,
            },
            {
                "id": "bb-002",
                "name": "WidgetCo Bug Bounty",
                "platform": "Bugcrowd",
                "scope": ["app.widgetco.io"],
                "max_payout": 5000,
                "status": "active",
                "findings_submitted": 1,
            },
        ],
        "total_earnings": 2750,
        "total": 2,
        "runbook": "SOC-BB-PROGRAMS-001",
    }


def integration_list_profile(_: Request, payload: dict[str, Any] | None) -> StaticProfile:
    return {
        "integrations": [
            {
                "id": "int-001",
                "name": "Slack",
                "type": "notification",
                "status": "connected",
                "last_sync": "2024-01-15T12:00:00Z",
            },
            {
                "id": "int-002",
                "name": "Jira",
                "type": "ticketing",
                "status": "connected",
                "last_sync": "2024-01-15T11:30:00Z",
            },
            {
                "id": "int-003",
                "name": "Splunk",
                "type": "siem",
                "status": "disconnected",
                "last_sync": None,
            },
            {
                "id": "int-004",
                "name": "PagerDuty",
                "type": "alerting",
                "status": "connected",
                "last_sync": "2024-01-15T10:00:00Z",
            },
            {
                "id": "int-005",
                "name": "GitHub",
                "type": "scm",
                "status": "connected",
                "last_sync": "2024-01-15T09:00:00Z",
            },
        ],
        "total": 5,
        "connected": 4,
        "runbook": "SOC-INT-LIST-001",
    }


def agent_register_profile(_: Request, payload: dict[str, Any] | None) -> StaticProfile:
    return {
        "agent_id": f"agent-demo-{int(time.time())}",
        "status": "registered_fallback",
        "api_key": "demo-agent-key-placeholder",
        "capabilities": ["scan", "recon", "report"],
        "heartbeat_interval": 30,
        "message": "Agent registered in degraded mode. Full connectivity pending service recovery.",
        "runbook": "SOC-AGENT-REG-001",
    }


def agent_list_profile(_: Request, payload: dict[str, Any] | None) -> StaticProfile:
    return {
        "agents": [
            {
                "id": "agent-001",
                "hostname": "scanner-node-01",
                "status": "online",
                "capabilities": ["nmap", "nikto", "nuclei"],
                "last_heartbeat": "2024-01-15T12:00:00Z",
                "tasks_completed": 142,
            },
            {
                "id": "agent-002",
                "hostname": "scanner-node-02",
                "status": "online",
                "capabilities": ["gobuster", "sqlmap", "ffuf"],
                "last_heartbeat": "2024-01-15T11:58:00Z",
                "tasks_completed": 89,
            },
            {
                "id": "agent-003",
                "hostname": "recon-node-01",
                "status": "offline",
                "capabilities": ["shodan", "virustotal", "dns"],
                "last_heartbeat": "2024-01-14T22:30:00Z",
                "tasks_completed": 210,
            },
        ],
        "total": 3,
        "online": 2,
        "runbook": "SOC-AGENT-LIST-001",
    }


STATIC_PROFILES = {
    "auth_login": auth_login_profile,
    "scan_create": scan_create_profile,
    "scan_get": scan_get_profile,
    "recon_lookup": recon_lookup_profile,
    "ai_health": ai_health_profile,
    "report_generate": report_generate_profile,
    "ai_analyze": ai_analyze_profile,
    "ai_correlate": ai_correlate_profile,
    "recon_dns": recon_dns_profile,
    "collab_rooms": collab_rooms_profile,
    "bugbounty_programs": bugbounty_programs_profile,
    "integration_list": integration_list_profile,
    "agent_register": agent_register_profile,
    "agent_list": agent_list_profile,
}
