"""Hybrid runtime routing for dynamic-first execution with static fallback."""

from __future__ import annotations

import os
import time
import uuid
from collections import deque
from enum import Enum
from typing import Any, Callable, Deque, Dict, Optional

import httpx
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse

from .policy_registry import get_policy

StaticHandler = Callable[[Request, Optional[Dict[str, Any]]], Dict[str, Any]]


class RuntimeMode(str, Enum):
    DYNAMIC = "dynamic"
    HYBRID = "hybrid"
    STATIC = "static"
    DEMO = "demo"
    EMERGENCY = "emergency"


class HybridRouter:
    def __init__(
        self,
        service_urls: Dict[str, str],
        *,
        static_profiles: Optional[Dict[str, StaticHandler]] = None,
    ) -> None:
        self.service_urls = service_urls
        self.static_profiles = static_profiles or {}
        env_mode = os.getenv("PLATFORM_RUNTIME_MODE", RuntimeMode.HYBRID.value).lower()
        self.default_mode = RuntimeMode(env_mode) if env_mode in RuntimeMode._value2member_map_ else RuntimeMode.HYBRID
        self.trace_export_url = os.getenv("COSMICSEC_TRACE_EXPORT_URL", "").strip()
        trace_buffer_size = int(os.getenv("COSMICSEC_TRACE_BUFFER_SIZE", "500"))
        self.trace_buffer: Deque[Dict[str, Any]] = deque(maxlen=max(10, trace_buffer_size))
        self.metrics = {
            "dynamic_total": 0,
            "dynamic_success": 0,
            "fallback_total": 0,
            "static_total": 0,
            "policy_denied_total": 0,
        }

    def resolve_mode(self, request: Request) -> RuntimeMode:
        header_mode = request.headers.get("X-Platform-Mode", "").strip().lower()
        if header_mode in RuntimeMode._value2member_map_:
            return RuntimeMode(header_mode)
        return self.default_mode

    async def execute(
        self,
        *,
        request: Request,
        service: str,
        path: str,
        method: str = "GET",
        payload: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 10.0,
        static_handler: Optional[StaticHandler] = None,
        route_key: Optional[str] = None,
    ) -> JSONResponse:
        decision_start = time.time()
        mode = self.resolve_mode(request)
        policy = get_policy(route_key)
        trace_id = request.headers.get("X-Request-Id", str(uuid.uuid4()))

        profile_handler = static_handler
        if profile_handler is None and policy is not None:
            profile_handler = self.static_profiles.get(policy.response_profile)

        async def _attach_contract(
            body: Dict[str, Any],
            *,
            route: str,
            degraded: bool,
            reason: Optional[str] = None,
            status_code: int = 200,
            outcome: str = "ok",
        ) -> JSONResponse:
            decision_ts = time.time()
            latency_ms = round((decision_ts - decision_start) * 1000, 2)
            body["_runtime"] = {
                "mode": mode.value,
                "route": route,
                "trace_id": trace_id,
                "route_key": route_key,
                "decision_ts": decision_ts,
                "latency_ms": latency_ms,
                "policy": policy.to_dict() if policy else None,
                "reason": reason,
            }
            body["_contract"] = {
                "schema": "cosmicsec.hybrid.v1",
                "version": "1.0.0",
                "degraded": degraded,
                "consumer_hint": "Check _runtime.route and _contract.degraded before privileged actions.",
            }
            event = {
                "trace_id": trace_id,
                "route_key": route_key,
                "mode": mode.value,
                "route": route,
                "status_code": status_code,
                "outcome": outcome,
                "degraded": degraded,
                "latency_ms": latency_ms,
                "reason": reason,
                "ts": decision_ts,
            }
            self.trace_buffer.append(event)
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
            if policy is not None and policy.auth_policy == "demo_only" and mode != RuntimeMode.DEMO:
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
            self.metrics["dynamic_total"] += 1
            async with httpx.AsyncClient() as client:
                response = await client.request(
                    method=method.upper(),
                    url=f"{self.service_urls[service]}{path}",
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

    def get_metrics(self) -> Dict[str, Any]:
        dynamic_total = self.metrics["dynamic_total"]
        dynamic_success = self.metrics["dynamic_success"]
        success_rate = (dynamic_success / dynamic_total) if dynamic_total else 0.0
        return {
            **self.metrics,
            "dynamic_success_rate": round(success_rate, 4),
        }

    async def _export_trace(self, event: Dict[str, Any]) -> None:
        if not self.trace_export_url:
            return
        try:
            async with httpx.AsyncClient() as client:
                await client.post(self.trace_export_url, json=event, timeout=1.5)
        except Exception:
            # Tracing export must never break request flow.
            return

    def get_recent_traces(self, limit: int = 50) -> list[Dict[str, Any]]:
        safe_limit = max(1, min(limit, 500))
        items = list(self.trace_buffer)
        return items[-safe_limit:]

    def get_tracing_status(self) -> Dict[str, Any]:
        return {
            "export_enabled": bool(self.trace_export_url),
            "export_url": self.trace_export_url or None,
            "buffer_size": self.trace_buffer.maxlen,
            "buffer_used": len(self.trace_buffer),
        }
