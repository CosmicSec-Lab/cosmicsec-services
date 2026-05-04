"""Runtime observability bootstrap for FastAPI services."""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import FastAPI


def _as_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def setup_observability(app: FastAPI, service_name: str, logger: logging.Logger) -> dict[str, Any]:
    """Initialize optional Sentry + OpenTelemetry instrumentation.

    This function is safe to call even when dependencies are missing.
    """
    state: dict[str, Any] = {
        "service": service_name,
        "sentry_enabled": False,
        "otel_enabled": False,
    }

    # -----------------------------
    # Sentry
    # -----------------------------
    sentry_dsn = os.getenv("SENTRY_DSN", "").strip()
    if sentry_dsn:
        try:
            import sentry_sdk
            from sentry_sdk.integrations.fastapi import FastApiIntegration

            traces_sample_rate = float(os.getenv("SENTRY_TRACES_SAMPLE_RATE", "0.1"))
            profiles_sample_rate = float(os.getenv("SENTRY_PROFILES_SAMPLE_RATE", "0.0"))
            sentry_sdk.init(
                dsn=sentry_dsn,
                environment=os.getenv("APP_ENV", "development"),
                integrations=[FastApiIntegration()],
                traces_sample_rate=traces_sample_rate,
                profiles_sample_rate=profiles_sample_rate,
            )
            state["sentry_enabled"] = True
            logger.info(
                "Sentry instrumentation enabled [service=%s]",
                service_name,
            )
        except Exception as exc:  # pragma: no cover - dependency/runtime optional
            logger.warning("Sentry initialization skipped [service=%s]: %s", service_name, exc)

    # -----------------------------
    # OpenTelemetry + OTLP (replaces deprecated Jaeger exporter)
    # -----------------------------
    # Default to disabled to avoid noisy exporter retry logs in local/dev stacks
    # where no OTLP collector is running. Enable explicitly with OTEL_ENABLED=true.
    otel_enabled = _as_bool(os.getenv("OTEL_ENABLED", "false"), default=False)
    if otel_enabled:
        try:
            from opentelemetry import trace
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            resource = Resource.create(
                {
                    "service.name": service_name,
                    "service.version": os.getenv("SERVICE_VERSION", "1.0.0"),
                    "deployment.environment": os.getenv("APP_ENV", "development"),
                }
            )
            provider = TracerProvider(resource=resource)

            otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://jaeger:4317")
            otlp_protocol = os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
            exporter = None
            exporter_name = "none"
            try:
                if otlp_protocol == "http":
                    from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                        OTLPSpanExporter,
                    )

                    exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
                else:
                    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                        OTLPSpanExporter,
                    )

                    exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
                exporter_name = f"otlp-{otlp_protocol}"
            except Exception as exc:  # pragma: no cover - depends on optional exporter versions
                logger.warning(
                    "OTLP exporter unavailable; traces will stay local [service=%s]: %s",
                    service_name,
                    exc,
                )
            if exporter is not None:
                provider.add_span_processor(BatchSpanProcessor(exporter))
            current_provider = trace.get_tracer_provider()
            if type(current_provider).__name__ == "ProxyTracerProvider":
                trace.set_tracer_provider(provider)
            else:
                provider = current_provider

            FastAPIInstrumentor.instrument_app(app, tracer_provider=provider)
            state["otel_enabled"] = True
            state["otel_exporter"] = exporter_name
            logger.info(
                "OpenTelemetry instrumentation enabled [service=%s exporter=%s endpoint=%s]",
                service_name,
                exporter_name,
                otlp_endpoint,
            )
        except Exception as exc:  # pragma: no cover - dependency/runtime optional
            logger.warning(
                "OpenTelemetry initialization skipped [service=%s]: %s", service_name, exc
            )

    return state
