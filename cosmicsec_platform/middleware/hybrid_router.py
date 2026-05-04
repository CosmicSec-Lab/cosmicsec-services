"""Hybrid runtime routing for dynamic-first execution with static fallback."""

from __future__ import annotations

import hashlib
import logging
import os
import time
import uuid
from collections import deque
from collections.abc import Callable
from enum import StrEnum
from typing import Any
from urllib.parse import urljoin

import httpx
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse

from cosmicsec_platform.contracts.runtime_metadata import HYBRID_SCHEMA, HYBRID_VERSION
from services.common.security_utils import validate_outbound_url

from .policy_registry import get_policy

StaticHandler = Callable[[Request, dict[str, Any] | None], dict[str, Any]]


class RuntimeMode(StrEnum):
    DYNAMIC = "dynamic"
    HYBRID = "hybrid"
    STATIC = "static"
    DEMO = "demo"
    EMERGENCY = "emergency"
    LOCAL_WEB = "local_web"


class HybridRouter:
    def __init__(
        self,
        service_urls: dict[str, str],
        *,
        static_profiles: dict[str, StaticHandler] | None = None,
    ) -> None:
        self.service_urls = service_urls
        self.static_profiles = static_profiles or {}
        self.logger = logging.getLogger(__name__)
        env_mode = os.getenv("PLATFORM_RUNTIME_MODE", RuntimeMode.HYBRID.value).lower()
        self.default_mode = (
            RuntimeMode(env_mode)
            if env_mode in RuntimeMode._value2member_map_
            else RuntimeMode.HYBRID
        )
        self.trace_export_url = os.getenv("COSMICSEC_TRACE_EXPORT_URL", "").strip()
        self.safe_service_urls = {
            name: validated
            for name, raw in service_urls.items()
            for validated in [validate_outbound_url(raw, allow_private_hosts=True)]
            if validated
        }
        self.canary_dynamic_percent = self._sanitize_percent(
            os.getenv("COSMICSEC_DYNAMIC_CANARY_PERCENT", "0")
        )
        trace_buffer_size = int(os.getenv("COSMICSEC_TRACE_BUFFER_SIZE", "500"))
        self.trace_buffer: deque[dict[str, Any]] = deque(maxlen=max(10, trace_buffer_size))
        self.metrics = {
            "dynamic_total": 0,
            "dynamic_success": 0,
            "fallback_total": 0,
            "static_total": 0,
            "policy_denied_total": 0,
        }

    def resolve_mode(self, request: Request) -> RuntimeMode:
        mode, _ = self.resolve_mode_with_context(request)
        return mode

    def resolve_mode_with_context(self, request: Request) -> tuple[RuntimeMode, dict[str, Any]]:
        header_mode = (
            (request.headers.get("X-CosmicSec-Mode") or request.headers.get("X-Platform-Mode", ""))
            .strip()
            .lower()
        )

        if header_mode in RuntimeMode._value2member_map_:
            return RuntimeMode(header_mode), {
                "source": "header",
                "canary_applied": False,
                "canary_bucket": None,
                "dynamic_canary_percent": self.canary_dynamic_percent,
            }

        if self.default_mode == RuntimeMode.HYBRID and self.canary_dynamic_percent > 0:
            canary_key = (
                request.headers.get("X-Canary-Key")
                or request.headers.get("X-Request-Id")
                or (request.client.host if request.client else "")
                or str(uuid.uuid4())
            )
            bucket = int(hashlib.sha256(canary_key.encode("utf-8")).hexdigest()[:8], 16) % 100
            if bucket < self.canary_dynamic_percent:
                return RuntimeMode.DYNAMIC, {
                    "source": "canary",
                    "canary_applied": True,
                    "canary_bucket": bucket,
                    "dynamic_canary_percent": self.canary_dynamic_percent,
                }
            return RuntimeMode.HYBRID, {
                "source": "default",
                "canary_applied": True,
                "canary_bucket": bucket,
                "dynamic_canary_percent": self.canary_dynamic_percent,
            }

        return self.default_mode, {
            "source": "default",
            "canary_applied": False,
            "canary_bucket": None,
            "dynamic_canary_percent": self.canary_dynamic_percent,
        }

    async def execute(
        self,
        *,
        request: Request,
        service: str,
        path: str,
        method: str = "GET",
        payload: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        static_handler: StaticHandler | None = None,
        route_key: str | None = None,
    ) -> JSONResponse:
        decision_start = time.time()
        mode, mode_context = self.resolve_mode_with_context(request)
        policy = get_policy(route_key)
        trace_id = request.headers.get("X-Request-Id", str(uuid.uuid4()))

        profile_handler = static_handler
        if profile_handler is None and policy is not None:
            profile_handler = self.static_profiles.get(policy.response_profile)

        async def _attach_contract(
            body: dict[str, Any],
            *,
            route: str,
            degraded: bool,
            reason: str | None = None,
            status_code: int = 200,
            outcome: str = "ok",
        ) -> JSONResponse:
            decision_ts = time.time()
            latency_ms = round((decision_ts - decision_start) * 1000, 2)
            body["_runtime"] = {
                "mode": mode.value,
                "mode_source": mode_context["source"],
                "canary_applied": mode_context["canary_applied"],
                "canary_bucket": mode_context["canary_bucket"],
                "dynamic_canary_percent": mode_context["dynamic_canary_percent"],
                "route": route,
                "trace_id": trace_id,
                "route_key": route_key,
                "decision_ts": decision_ts,
                "latency_ms": latency_ms,
                "policy": policy.to_dict() if policy else None,
                "reason": reason,
            }
            body["_contract"] = {
                "schema": HYBRID_SCHEMA,
                "version": HYBRID_VERSION,
                "degraded": degraded,
                "consumer_hint": "Check _runtime.route and _contract.degraded before privileged actions.",
            }
            event = {
                "trace_id": trace_id,
                "route_key": route_key,
                "mode": mode.value,
                "mode_source": mode_context["source"],
                "route": route,
                "status_code": status_code,
                "outcome": outcome,
                "degraded": degraded,
                "latency_ms": latency_ms,
                "reason": reason,
                "ts": decision_ts,
            }
            self.trace_buffer.append(event)
            if route in ("static", "static_fallback", "policy_denied"):
                self.logger.warning(
                    "Hybrid degraded decision route=%s route_key=%s mode=%s status=%s reason=%s trace_id=%s",
                    route,
                    route_key,
                    mode.value,
                    status_code,
                    reason,
                    trace_id,
                )
            await self._export_trace(event)
            return JSONResponse(status_code=status_code, content=body)

        if mode in (RuntimeMode.STATIC, RuntimeMode.DEMO, RuntimeMode.EMERGENCY):
            if policy is not None and policy.fallback_policy == "disabled":
                self.metrics["policy_denied_total"] += 1
                return await _attach_contract(
                    {"status": "denied", "detail": "Fallback disabled by policy."},
                    route="policy_denied",
                    degraded=True,
                    status_code=503,
                    outcome="policy_denied",
                )
            if (
                policy is not None
                and policy.auth_policy == "demo_only"
                and mode != RuntimeMode.DEMO
            ):
                self.metrics["policy_denied_total"] += 1
                return await _attach_contract(
                    {"status": "denied", "detail": "Static auth fallback is demo-only."},
                    route="policy_denied",
                    degraded=True,
                    status_code=403,
                    outcome="policy_denied",
                )
            if profile_handler is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=f"No static handler for {service}",
                )
            self.metrics["static_total"] += 1
            body = profile_handler(request, payload)
            return await _attach_contract(body, route="static", degraded=True, outcome="static")

        try:
            safe_base = self.safe_service_urls.get(service)
            if not safe_base:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=f"Unknown or unsafe service endpoint: {service}",
                )
            safe_path = "/" + str(path or "").lstrip("/")
            if "//" in safe_path or safe_path.lower().startswith("/http"):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid service path",
                )
            self.metrics["dynamic_total"] += 1
            async with httpx.AsyncClient() as client:
                response = await client.request(
                    method=method.upper(),
                    url=urljoin(safe_base.rstrip("/") + "/", safe_path.lstrip("/")),
                    json=payload,
                    params=params,
                    headers=headers,
                    timeout=timeout,
                )
            content = response.json()
            if isinstance(content, dict):
                self.metrics["dynamic_success"] += 1
                return await _attach_contract(
                    content,
                    route="dynamic",
                    degraded=False,
                    status_code=response.status_code,
                    outcome="dynamic",
                )
            return JSONResponse(status_code=response.status_code, content=content)
        except (httpx.HTTPError, ValueError) as exc:
            if mode == RuntimeMode.HYBRID and profile_handler is not None:
                if policy is not None and policy.fallback_policy == "disabled":
                    self.metrics["policy_denied_total"] += 1
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail=f"{service} service unavailable and fallback disabled",
                    ) from exc
                self.metrics["fallback_total"] += 1
                body = profile_handler(request, payload)
                return await _attach_contract(
                    body,
                    route="static_fallback",
                    degraded=True,
                    reason=str(exc),
                    outcome="fallback",
                )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"{service} service unavailable",
            ) from exc

    def get_metrics(self) -> dict[str, Any]:
        dynamic_total = self.metrics["dynamic_total"]
        dynamic_success = self.metrics["dynamic_success"]
        success_rate = (dynamic_success / dynamic_total) if dynamic_total else 0.0
        return {
            **self.metrics,
            "dynamic_success_rate": round(success_rate, 4),
        }

    async def _export_trace(self, event: dict[str, Any]) -> None:
        if not self.trace_export_url:
            return
        try:
            async with httpx.AsyncClient() as client:
                await client.post(self.trace_export_url, json=event, timeout=1.5)
        except Exception:
            return

    def get_recent_traces(self, limit: int = 50) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 500))
        items = list(self.trace_buffer)
        return items[-safe_limit:]

    def get_tracing_status(self) -> dict[str, Any]:
        return {
            "export_enabled": bool(self.trace_export_url),
            "export_url": self.trace_export_url or None,
            "buffer_size": self.trace_buffer.maxlen,
            "buffer_used": len(self.trace_buffer),
        }

    def get_rollout_config(self) -> dict[str, Any]:
        return {
            "default_mode": self.default_mode.value,
            "dynamic_canary_percent": self.canary_dynamic_percent,
        }

    def set_rollout_config(self, dynamic_canary_percent: int) -> dict[str, Any]:
        self.canary_dynamic_percent = self._sanitize_percent(dynamic_canary_percent)
        return self.get_rollout_config()

    @staticmethod
    def _sanitize_percent(value: Any) -> int:
        try:
            percent = int(value)
        except (TypeError, ValueError):
            return 0
        return max(0, min(percent, 100))
