"""GraphQL runtime endpoint for the API gateway."""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import FastAPI

SCHEMA = """
type Query {
  health: Health!
  dashboard: DashboardOverview!
  scans(limit: Int = 10, offset: Int = 0): [Scan!]!
  scan(id: ID!): Scan
  scanFindings(scanId: ID!): [Finding!]!
  agents: [Agent!]!
}

type Mutation {
  createScan(target: String!, scanTypes: [String!]!): Scan!
}

type Health {
  status: String!
  service: String!
}

type DashboardOverview {
  total_scans: Int!
  critical_findings: Int!
  active_agents: Int!
  open_bugs: Int!
  security_score: Int!
  findings_last_7d: Int!
  compliance_pct: Int!
}

type Scan {
  id: ID!
  target: String!
  status: String!
  progress: Int!
  findings_count: Int
}

type Finding {
  id: ID!
  scan_id: ID!
  title: String!
  severity: String!
  description: String!
  recommendation: String!
}

type ToolInfo {
  name: String
  path: String
  version: String
  capabilities: [String!]
}

type Agent {
  agent_id: ID!
  status: String
  registered_at: Float
  last_seen_at: Float
  manifest: AgentManifest
}

type AgentManifest {
  hostname: String
  platform: String
  tools: [ToolInfo!]
}
"""


def _extract_data(payload: Any) -> Any:
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


async def _request_json(url: str, method: str = "GET", json_body: dict | None = None) -> Any:
    async with httpx.AsyncClient() as client:
        if method == "GET":
            resp = await client.get(url, timeout=8.0)
        else:
            resp = await client.post(url, json=json_body or {}, timeout=12.0)
    resp.raise_for_status()
    return _extract_data(resp.json())


def mount_graphql(app: FastAPI, service_urls: dict[str, str], logger) -> bool:
    """Mount /graphql if Ariadne is available."""
    try:
        from ariadne import MutationType, QueryType, make_executable_schema
        from ariadne.asgi import GraphQL
    except Exception as exc:  # pragma: no cover
        logger.warning("GraphQL runtime unavailable (Ariadne import failed): %s", exc)
        return False

    query = QueryType()
    mutation = MutationType()

    @query.field("health")
    async def resolve_health(*_) -> dict:
        return {"status": "healthy", "service": "api-gateway"}

    @query.field("dashboard")
    async def resolve_dashboard(*_) -> dict:
        data = await _request_json(f"{service_urls['gateway']}/api/dashboard/overview")
        return data

    @query.field("scans")
    async def resolve_scans(*_, limit: int = 10, offset: int = 0) -> list[dict]:
        url = f"{service_urls['scan']}/scans?limit={limit}&offset={offset}"
        data = await _request_json(url)
        return data if isinstance(data, list) else []

    @query.field("scan")
    async def resolve_scan(*_, id: str) -> dict | None:
        return await _request_json(f"{service_urls['scan']}/scans/{id}")

    @query.field("scanFindings")
    async def resolve_scan_findings(*_, scanId: str) -> list[dict]:
        data = await _request_json(f"{service_urls['scan']}/scans/{scanId}/findings")
        return data if isinstance(data, list) else []

    @query.field("agents")
    async def resolve_agents(*_) -> list[dict]:
        try:
            payload = await _request_json(f"{service_urls['agent_relay']}/relay/agents")
            if isinstance(payload, dict):
                return payload.get("agents", [])
        except Exception:
            return []
        return []

    @mutation.field("createScan")
    async def resolve_create_scan(*_, target: str, scanTypes: list[str]) -> dict:
        return await _request_json(
            f"{service_urls['scan']}/scans",
            method="POST",
            json_body={"target": target, "scan_types": scanTypes},
        )

    schema = make_executable_schema(SCHEMA, [query, mutation])
    app.mount("/graphql", GraphQL(schema, debug=False))
    logger.info("GraphQL endpoint mounted at /graphql")
    return True
