"""Compatibility wrapper for extracted shared middleware package."""

from cosmicsec_platform.middleware.policy_registry import ROUTE_POLICIES, RoutePolicy, get_policy

__all__ = ["RoutePolicy", "ROUTE_POLICIES", "get_policy"]
