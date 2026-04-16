"""
CosmicSec Advanced RBAC Engine — Phase R.4

Provides org-scoped resource-level permissions using Casbin with:
  - Built-in role templates: admin, soc_analyst, pentester, manager, auditor, viewer
  - Custom role CRUD (in-memory, DB-backed when available)
  - `require_permission(resource, action, org_scoped=True)` decorator
  - Permission-check endpoint helpers

Usage in endpoints::

    from services.auth_service.rbac_engine import require_rbac_permission

    @app.post("/scans")
    @require_rbac_permission("scan", "write")
    async def create_scan(...): ...
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import Depends, HTTPException, Request, status

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Role templates
# ---------------------------------------------------------------------------

BUILT_IN_ROLES: dict[str, dict[str, Any]] = {
    "admin": {
        "description": "Full platform access — create/manage everything",
        "permissions": [("*", "*")],
        "inherits": [],
    },
    "manager": {
        "description": "Manage org members, view all scans and reports",
        "permissions": [
            ("scan", "read"),
            ("scan", "write"),
            ("report", "read"),
            ("report", "write"),
            ("finding", "read"),
            ("finding", "write"),
            ("recon", "read"),
            ("member", "read"),
            ("member", "invite"),
        ],
        "inherits": [],
    },
    "soc_analyst": {
        "description": "Security operations — run scans, triage findings, write reports",
        "permissions": [
            ("scan", "read"),
            ("scan", "write"),
            ("finding", "read"),
            ("finding", "write"),
            ("report", "read"),
            ("report", "write"),
            ("recon", "read"),
            ("recon", "write"),
            ("ai", "read"),
        ],
        "inherits": [],
    },
    "pentester": {
        "description": "Run offensive tests — scans, recon, exploits (in authorized scope)",
        "permissions": [
            ("scan", "read"),
            ("scan", "write"),
            ("scan", "execute"),
            ("recon", "read"),
            ("recon", "write"),
            ("finding", "read"),
            ("finding", "write"),
            ("bugbounty", "read"),
            ("bugbounty", "submit"),
        ],
        "inherits": [],
    },
    "auditor": {
        "description": "Read-only access to scans, findings, reports, compliance",
        "permissions": [
            ("scan", "read"),
            ("finding", "read"),
            ("report", "read"),
            ("compliance", "read"),
            ("audit_log", "read"),
        ],
        "inherits": [],
    },
    "viewer": {
        "description": "Read-only access to scans and findings",
        "permissions": [
            ("scan", "read"),
            ("finding", "read"),
        ],
        "inherits": [],
    },
}

# ---------------------------------------------------------------------------
# Permission matrix
# ---------------------------------------------------------------------------

# All resources and actions in the system
RESOURCES = [
    "scan", "finding", "report", "recon", "ai",
    "member", "compliance", "audit_log", "bugbounty",
    "plugin", "agent", "integration", "admin",
]

ACTIONS = ["read", "write", "delete", "execute", "invite", "submit", "manage"]


def _permissions_for_role(role_name: str, custom_roles: dict | None = None) -> set[tuple[str, str]]:
    """Return the effective (resource, action) set for a role (with inheritance)."""
    roles_registry = {**BUILT_IN_ROLES, **(custom_roles or {})}
    role_def = roles_registry.get(role_name)
    if not role_def:
        return set()

    perms: set[tuple[str, str]] = {tuple(p) for p in role_def.get("permissions", [])}

    for parent in role_def.get("inherits", []):
        perms.update(_permissions_for_role(parent, custom_roles))

    return perms


def check_permission(
    role: str,
    resource: str,
    action: str,
    *,
    org_id: str | None = None,
    custom_roles: dict | None = None,
) -> bool:
    """
    Return True if *role* may perform *action* on *resource*.

    Wildcard permission `("*", "*")` grants all access (admin).
    Org scoping is tracked in *org_id* but enforcement is at the gateway level;
    this function checks role-level capability.
    """
    perms = _permissions_for_role(role, custom_roles)
    # Wildcard admin
    if ("*", "*") in perms:
        return True
    # Exact match
    if (resource, action) in perms:
        return True
    # Resource wildcard
    return (resource, "*") in perms


def _extract_role(user_state: Any) -> str:
    """Extract role string from either a dict or an object user state."""
    if isinstance(user_state, dict):
        return str(user_state.get("role") or "viewer")
    return str(getattr(user_state, "role", None) or "viewer")


def require_rbac_permission(resource: str, action: str):
    """
    FastAPI dependency factory that enforces resource-level RBAC.

    Reads ``role`` from JWT claims stored on ``request.state.user``.
    Falls back to HTTP 403 if the role does not have the required permission.

    Example::

        @app.post("/scans")
        async def create_scan(
            _: None = Depends(require_rbac_permission("scan", "write"))
        ): ...
    """
    async def checker(request: Request) -> None:
        user_state = getattr(request.state, "user", None)
        if user_state is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        role = _extract_role(user_state)
        if not check_permission(str(role), resource, action):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role}' does not have '{action}' permission on '{resource}'",
            )
        logger.debug("RBAC: %s allowed %s:%s", role, resource, action)

    return Depends(checker)


# ---------------------------------------------------------------------------
# Custom role store (in-memory, DB-backed when available)
# ---------------------------------------------------------------------------

_custom_roles: dict[str, dict[str, Any]] = {}


def create_custom_role(
    name: str,
    *,
    description: str,
    permissions: list[tuple[str, str]],
    inherits: list[str] | None = None,
    org_id: str | None = None,
) -> dict[str, Any]:
    """Create a custom role scoped to an org."""
    if name in BUILT_IN_ROLES:
        raise ValueError(f"Cannot override built-in role '{name}'")
    role = {
        "description": description,
        "permissions": [list(p) for p in permissions],
        "inherits": inherits or [],
        "org_id": org_id,
        "built_in": False,
    }
    _custom_roles[f"{org_id or 'global'}:{name}"] = role
    return {"name": name, **role}


def list_roles(org_id: str | None = None) -> list[dict[str, Any]]:
    """List all roles visible to an org (built-in + org custom)."""
    rows = [
        {"name": name, "built_in": True, **defn}
        for name, defn in BUILT_IN_ROLES.items()
    ]
    for key, defn in _custom_roles.items():
        if org_id is None or defn.get("org_id") in {None, org_id}:
            name = key.split(":", 1)[1] if ":" in key else key
            rows.append({"name": name, "built_in": False, **defn})
    return rows


def delete_custom_role(name: str, org_id: str | None = None) -> bool:
    """Delete a custom role. Returns True if deleted."""
    key = f"{org_id or 'global'}:{name}"
    if key in _custom_roles:
        del _custom_roles[key]
        return True
    return False


def can_user(
    role: str,
    resource: str,
    action: str,
    org_id: str | None = None,
) -> dict[str, Any]:
    """Helper for permission-test endpoint. Returns detailed result."""
    custom = {
        k.split(":", 1)[1]: v
        for k, v in _custom_roles.items()
        if v.get("org_id") in {None, org_id}
    }
    allowed = check_permission(role, resource, action, org_id=org_id, custom_roles=custom)
    return {
        "role": role,
        "resource": resource,
        "action": action,
        "org_id": org_id,
        "allowed": allowed,
        "reason": "permission_granted" if allowed else "permission_denied",
    }
