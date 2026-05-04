"""Hybrid route policy registry used by API gateway runtime decisions."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class RoutePolicy:
    route_key: str
    criticality: str  # business_critical | security_critical | non_critical
    fallback_policy: str  # allowed | partial | disabled
    auth_policy: str  # deny | demo_only | limited
    response_profile: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


ROUTE_POLICIES: dict[str, RoutePolicy] = {
    "auth.login": RoutePolicy(
        route_key="auth.login",
        criticality="security_critical",
        fallback_policy="partial",
        auth_policy="demo_only",
        response_profile="auth_login",
    ),
    "auth.refresh": RoutePolicy(
        route_key="auth.refresh",
        criticality="security_critical",
        fallback_policy="disabled",
        auth_policy="deny",
        response_profile="auth_refresh",
    ),
    "scan.create": RoutePolicy(
        route_key="scan.create",
        criticality="business_critical",
        fallback_policy="allowed",
        auth_policy="limited",
        response_profile="scan_create",
    ),
    "scan.get": RoutePolicy(
        route_key="scan.get",
        criticality="business_critical",
        fallback_policy="partial",
        auth_policy="limited",
        response_profile="scan_get",
    ),
    "recon.lookup": RoutePolicy(
        route_key="recon.lookup",
        criticality="non_critical",
        fallback_policy="allowed",
        auth_policy="limited",
        response_profile="recon_lookup",
    ),
    "ai.health": RoutePolicy(
        route_key="ai.health",
        criticality="non_critical",
        fallback_policy="allowed",
        auth_policy="limited",
        response_profile="ai_health",
    ),
    "ai.analyze": RoutePolicy(
        route_key="ai.analyze",
        criticality="security_critical",
        fallback_policy="disabled",
        auth_policy="deny",
        response_profile="ai_analyze",
    ),
    "report.generate": RoutePolicy(
        route_key="report.generate",
        criticality="business_critical",
        fallback_policy="partial",
        auth_policy="limited",
        response_profile="report_generate",
    ),
}


def get_policy(route_key: str | None) -> RoutePolicy | None:
    if not route_key:
        return None
    return ROUTE_POLICIES.get(route_key)
