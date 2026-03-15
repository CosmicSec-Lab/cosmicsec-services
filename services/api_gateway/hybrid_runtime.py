"""Hybrid runtime routing for dynamic-first execution with static fallback."""

from __future__ import annotations

import os
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Optional

import httpx
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse

StaticHandler = Callable[[Request, Optional[Dict[str, Any]]], Dict[str, Any]]


class RuntimeMode(str, Enum):
    DYNAMIC = "dynamic"
    HYBRID = "hybrid"
    STATIC = "static"
    DEMO = "demo"
    EMERGENCY = "emergency"


class HybridRouter:
    def __init__(self, service_urls: Dict[str, str]) -> None:
        self.service_urls = service_urls
        env_mode = os.getenv("PLATFORM_RUNTIME_MODE", RuntimeMode.HYBRID.value).lower()
        self.default_mode = RuntimeMode(env_mode) if env_mode in RuntimeMode._value2member_map_ else RuntimeMode.HYBRID

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
    ) -> JSONResponse:
        mode = self.resolve_mode(request)

        if mode in (RuntimeMode.STATIC, RuntimeMode.DEMO, RuntimeMode.EMERGENCY):
            if static_handler is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=f"No static handler for {service}",
                )
            body = static_handler(request, payload)
            body["_runtime"] = {"mode": mode.value, "route": "static"}
            return JSONResponse(status_code=200, content=body)

        try:
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
                content["_runtime"] = {"mode": mode.value, "route": "dynamic"}
            return JSONResponse(status_code=response.status_code, content=content)
        except (httpx.HTTPError, ValueError) as exc:
            if mode == RuntimeMode.HYBRID and static_handler is not None:
                body = static_handler(request, payload)
                body["_runtime"] = {
                    "mode": mode.value,
                    "route": "static_fallback",
                    "reason": str(exc),
                }
                return JSONResponse(status_code=200, content=body)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"{service} service unavailable",
            ) from exc
