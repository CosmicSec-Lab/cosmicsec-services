"""
Phase P.2 — Rust Ingest Engine bridge for the CosmicSec API Gateway.

Provides a thin Python interface that routes ingest requests to the Rust engine
via gRPC when it is available, and falls back to the Python-based parsers in
scan_service when the Rust engine is unhealthy or the feature flag is disabled.

Feature flag:  COSMICSEC_USE_RUST_INGEST=true|false  (default: false)
Rust endpoint: COSMICSEC_INGEST_GRPC_ADDR  (default: ingest:50051)
Rust health:   COSMICSEC_INGEST_HEALTH_URL (default: http://ingest:8099/health)
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_USE_RUST_INGEST = os.getenv("COSMICSEC_USE_RUST_INGEST", "false").lower() in ("1", "true", "yes")
_INGEST_HEALTH_URL = os.getenv("COSMICSEC_INGEST_HEALTH_URL", "http://ingest:8099/health")
_INGEST_GRPC_ADDR = os.getenv("COSMICSEC_INGEST_GRPC_ADDR", "ingest:50051")

# Cache of last health check result to avoid hammering the Rust service
_rust_engine_healthy: bool | None = None


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


async def check_rust_ingest_health() -> bool:
    """Return True if the Rust ingest engine is reachable and healthy."""
    global _rust_engine_healthy  # noqa: PLW0603
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            resp = await client.get(_INGEST_HEALTH_URL)
            _rust_engine_healthy = resp.status_code == 200
    except Exception as exc:
        logger.warning("Rust ingest engine health check failed: %s", exc)
        _rust_engine_healthy = False
    return bool(_rust_engine_healthy)


# ---------------------------------------------------------------------------
# gRPC stub (dynamically imported so the gateway starts without grpcio)
# ---------------------------------------------------------------------------


def _get_grpc_stub() -> Any | None:
    """Return a connected gRPC IngestService stub, or None if unavailable."""
    try:
        import grpc  # type: ignore[import-untyped]

        # Attempt to import generated stubs; fall back gracefully if not present
        try:
            from services.api_gateway import (  # type: ignore[import-not-found]
                ingest_pb2,
                ingest_pb2_grpc,
            )

            channel = grpc.insecure_channel(_INGEST_GRPC_ADDR)
            return ingest_pb2_grpc.IngestServiceStub(channel), ingest_pb2
        except ImportError:
            logger.debug("ingest gRPC stubs not generated yet — falling back to HTTP relay")
            return None, None
    except ImportError:
        logger.debug("grpcio not installed — Rust ingest gRPC unavailable")
        return None, None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def ingest_batch(
    tool: str,
    raw_data: bytes,
    scan_id: str,
) -> dict[str, Any]:
    """
    Ingest raw scanner output and return normalised findings.

    Route:
      1. If COSMICSEC_USE_RUST_INGEST=true AND the Rust engine is healthy →
         forward to Rust gRPC IngestService.IngestBatch.
      2. Otherwise → return a signal that callers should use the Python
         scan_service parser (lightweight fallback).

    Returns a dict with keys:
      ``routed_to``: "rust" | "python_fallback"
      ``findings``:  list[dict] — populated only when routed_to="rust"
      ``message``:   str        — human-readable status
    """
    if not _USE_RUST_INGEST:
        return {"routed_to": "python_fallback", "findings": [], "message": "Rust ingest disabled"}

    healthy = await check_rust_ingest_health()
    if not healthy:
        logger.warning(
            "Rust ingest engine unhealthy — falling back to Python parsers for scan %s", scan_id
        )
        return {
            "routed_to": "python_fallback",
            "findings": [],
            "message": "Rust ingest engine unhealthy; using Python parser",
        }

    stub, pb2 = _get_grpc_stub()
    if stub is None:
        return {
            "routed_to": "python_fallback",
            "findings": [],
            "message": "gRPC stubs unavailable; using Python parser",
        }

    try:
        request = pb2.IngestRequest(  # type: ignore[union-attr]
            scan_id=scan_id,
            tool=tool,
            raw_data=raw_data,
        )
        response = stub.IngestBatch(request, timeout=30)  # type: ignore[union-attr]
        findings = [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "target": f.target,
                "tool": f.tool,
                "timestamp": f.timestamp,
            }
            for f in response.findings
        ]
        logger.info(
            "Rust ingest engine processed %d findings for scan %s", len(findings), scan_id
        )
        return {
            "routed_to": "rust",
            "findings": findings,
            "message": f"Processed {len(findings)} findings via Rust engine",
        }
    except Exception as exc:
        logger.error("Rust ingest gRPC call failed: %s — falling back to Python parsers", exc)
        return {
            "routed_to": "python_fallback",
            "findings": [],
            "message": f"Rust engine error: {exc}; using Python parser",
        }
