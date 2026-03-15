"""Phase 4 AI Red Team planning with strict safety guardrails."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List


SAFE_TECHNIQUES = {
    "recon": ["asset_inventory", "attack_surface_mapping", "service_enumeration"],
    "initial_access": ["credential_hygiene_validation", "phishing_simulation_review"],
    "execution": ["input_validation_tests", "safe_payload_replay"],
    "persistence": ["session_policy_review", "token_lifetime_review"],
    "impact": ["backup_restore_validation", "detection_rule_validation"],
}


@dataclass(frozen=True)
class RedTeamScope:
    target: str
    authorized: bool
    environment: str
    objectives: List[str]


def validate_safety(scope: RedTeamScope) -> Dict[str, object]:
    issues: List[str] = []
    if not scope.authorized:
        issues.append("Authorization is required before generating red-team plans.")
    if scope.environment.lower() not in {"lab", "staging", "production-approved"}:
        issues.append("Environment must be one of: lab, staging, production-approved.")
    if not scope.objectives:
        issues.append("At least one objective must be provided.")

    return {
        "is_safe": len(issues) == 0,
        "issues": issues,
        "checked_at": datetime.utcnow().isoformat(),
    }


def select_exploit_logic(objectives: List[str]) -> List[Dict[str, str]]:
    selected: List[Dict[str, str]] = []
    lower_objectives = " ".join(objectives).lower()

    for stage, techniques in SAFE_TECHNIQUES.items():
        technique = techniques[0]
        if "credential" in lower_objectives and stage == "initial_access":
            technique = "credential_hygiene_validation"
        if "api" in lower_objectives and stage == "execution":
            technique = "input_validation_tests"
        selected.append(
            {
                "stage": stage,
                "technique": technique,
                "mode": "defensive-simulation",
            }
        )
    return selected


def plan_attack_chain(scope: RedTeamScope) -> Dict[str, object]:
    safety = validate_safety(scope)
    if not safety["is_safe"]:
        return {
            "status": "blocked",
            "target": scope.target,
            "safety": safety,
            "plan": [],
            "next_steps": ["Provide explicit authorization and approved environment metadata."],
        }

    techniques = select_exploit_logic(scope.objectives)
    chain = []
    for index, item in enumerate(techniques, start=1):
        chain.append(
            {
                "step": index,
                "stage": item["stage"],
                "technique": item["technique"],
                "goal": f"Validate controls for {item['stage'].replace('_', ' ')}.",
                "evidence_required": ["logs", "detections", "response_notes"],
            }
        )

    return {
        "status": "planned",
        "target": scope.target,
        "environment": scope.environment,
        "objectives": scope.objectives,
        "safety": safety,
        "plan": chain,
        "generated_at": datetime.utcnow().isoformat(),
    }
