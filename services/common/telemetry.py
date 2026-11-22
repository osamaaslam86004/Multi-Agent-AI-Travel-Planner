from services.core.config import get_settings

"""
OpenTelemetry Tracing, W3C Context Propagation, Structured JSON Logging,
and Bounded Prometheus Metrics for Multi-Agent Infrastructure.
"""
import contextvars
import json
import logging
import os
import random
import re
import time
from contextlib import asynccontextmanager, contextmanager
from typing import Any

# OpenTelemetry Imports with graceful fallback
from opentelemetry import trace
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

OPENTELEMETRY_AVAILABLE = True
# Context Variables for Log Correlation across Threads / Async Tasks
correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "correlation_id", default="none"
)
tenant_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "tenant_id", default="default"
)
# W3C traceparent regex: 00-{32 hex trace_id}-{16 hex parent_id}-{2 hex flags}
TRACEPARENT_REGEX = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


def generate_traceparent() -> str:
    """Generate a valid W3C traceparent header."""
    trace_id = f"{random.getrandbits(128):032x}"
    span_id = f"{random.getrandbits(64):016x}"
    trace_flags = "01"  # sampled
    return f"00-{trace_id}-{span_id}-{trace_flags}"


def extract_traceparent(headers: dict[str, Any]) -> str:
    """Extract or generate a W3C traceparent header from headers."""
    for key, value in headers.items():
        if (
            key.lower() == "traceparent"
            and isinstance(value, str)
            and TRACEPARENT_REGEX.match(value)
        ):
            return value
    return generate_traceparent()


def inject_traceparent(
    carrier: dict[str, Any], traceparent: str | None = None
) -> dict[str, Any]:
    """Inject W3C traceparent into carrier dictionary."""
    tp = traceparent or generate_traceparent()
    carrier["traceparent"] = tp
    TraceContextTextMapPropagator().inject(carrier)
    return carrier


def extract_otel_context(carrier: dict[str, Any]):
    """Extract OpenTelemetry context from carrier dictionary."""
    return TraceContextTextMapPropagator().extract(carrier)


_tracer_provider = None


def setup_telemetry(service_name: str = "travelbrain", app=None):
    """
    Configures OpenTelemetry TracerProvider with OTLP Exporter
    and instruments FastAPI, HTTPX, and Redis if available.
    """
    global _tracer_provider
    if not OPENTELEMETRY_AVAILABLE:
        return None
    try:
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        endpoint = os.getenv(
            "OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318/v1/traces"
        )
        resource = Resource.create(
            {
                "service.name": service_name,
                "environment": get_settings().app.environment,
            }
        )
        provider = TracerProvider(resource=resource)
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )

            exporter = OTLPSpanExporter(endpoint=endpoint)
            provider.add_span_processor(BatchSpanProcessor(exporter))
        except (ImportError, OSError, RuntimeError, ValueError) as exc:
            logging.getLogger("travelbrain.telemetry").debug(
                "OTLP exporter unavailable, falling back to console exporter: %s", exc
            )
            try:
                from opentelemetry.sdk.trace.export import ConsoleSpanExporter

                provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
            except (ImportError, OSError, RuntimeError, ValueError) as console_exc:
                logging.getLogger("travelbrain.telemetry").debug(
                    "Console exporter unavailable: %s", console_exc
                )
        trace.set_tracer_provider(provider)
        _tracer_provider = provider
        if app is not None:
            try:
                from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

                FastAPIInstrumentor.instrument_app(app, tracer_provider=provider)
            except (ImportError, OSError, RuntimeError, ValueError) as e:
                logging.getLogger("travelbrain.telemetry").debug(
                    "FastAPI instrumentation skipped: %s", e
                )
        try:
            from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

            HTTPXClientInstrumentor().instrument()
        except (ImportError, OSError, RuntimeError, ValueError) as exc:
            logging.getLogger("travelbrain.telemetry").debug(
                "HTTPX instrumentation skipped: %s", exc
            )
        try:
            from opentelemetry.instrumentation.redis import RedisInstrumentor

            RedisInstrumentor().instrument()
        except (ImportError, OSError, RuntimeError, ValueError) as exc:
            logging.getLogger("travelbrain.telemetry").debug(
                "Redis instrumentation skipped: %s", exc
            )
        return provider
    except (ImportError, OSError, RuntimeError, ValueError) as e:
        logging.getLogger("travelbrain.telemetry").warning(
            "OpenTelemetry setup fallback: %s", e
        )
        return None


def get_tracer(service_name: str = "travelbrain"):
    """Returns an OpenTelemetry tracer for the specified service name."""
    if OPENTELEMETRY_AVAILABLE and trace:
        return trace.get_tracer(service_name)
    return trace.NoOpTracer()


# ============================================================================
# Structured JSON Logger
# ============================================================================
class JSONFormatter(logging.Formatter):
    """
    Structured JSON Log Formatter outputting fields:
    timestamp, level, logger, message, trace_id, span_id, correlation_id, tenant_id.
    """

    def format(self, record: logging.LogRecord) -> str:
        trace_id = "0" * 32
        span_id = "0" * 16
        if OPENTELEMETRY_AVAILABLE and trace:
            current_span = trace.get_current_span()
            span_ctx = current_span.get_span_context() if current_span else None
            if span_ctx and span_ctx.is_valid:
                trace_id = f"{span_ctx.trace_id:032x}"
                span_id = f"{span_ctx.span_id:016x}"
        log_data = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "trace_id": trace_id,
            "span_id": span_id,
            "correlation_id": correlation_id_var.get(),
            "tenant_id": tenant_id_var.get(),
        }
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_data)


def configure_structured_logging(level: int = logging.INFO) -> None:
    """Applies structured JSON logging to the root logger."""
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(JSONFormatter())
    root_logger.addHandler(console_handler)


def set_log_context(correlation_id: str, tenant_id: str) -> None:
    """Helper to set correlation and tenant ID context for logging."""
    correlation_id_var.set(correlation_id)
    tenant_id_var.set(tenant_id)


# ============================================================================
# Bounded Metrics Collection (Prometheus / OTel compatible)
# ============================================================================
try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )

    OPERATION_DURATION_SECONDS = Histogram(
        "travelbrain_operation_duration_seconds",
        "Duration of service operations or HTTP requests in seconds",
        labelnames=("service", "operation", "status"),
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    )
    STREAM_LAG_GAUGE = Gauge(
        "travelbrain_stream_lag_messages",
        "Stream lag count per stream and group",
        ["stream", "group"],
    )
    PENDING_ENTRY_AGE_GAUGE = Gauge(
        "travelbrain_pending_entry_age_seconds",
        "Oldest pending entry age in seconds",
        ["stream", "group"],
    )
    BARRIER_AGE_GAUGE = Gauge(
        "travelbrain_barrier_age_seconds",
        "Age of active barriers in seconds",
        ["status"],
    )
    CIRCUIT_BREAKER_STATE_GAUGE = Gauge(
        "travelbrain_circuit_breaker_state",
        "Circuit Breaker State (0=CLOSED, 1=HALF_OPEN, 2=OPEN)",
        ["provider"],
    )
    REQUESTS_TOTAL = Counter(
        "travelbrain_requests_total",
        "Total requests processed",
        ["domain", "status"],
    )
    DEGRADED_REQUESTS_TOTAL = Counter(
        "travelbrain_degraded_requests_total",
        "Total requests operating in degraded mode",
        ["domain"],
    )
    ACTIVE_SSE_CONNECTIONS_GAUGE = Gauge(
        "travelbrain_active_sse_connections",
        "Count of active SSE streaming connections",
    )
    LLM_TOKENS_COUNTER = Counter(
        "travelbrain_llm_tokens_total",
        "Total LLM tokens consumed",
        ["tenant_id", "provider", "model", "type"],
    )
    LLM_COST_COUNTER = Counter(
        "travelbrain_llm_cost_dollars_total",
        "Total estimated LLM cost in USD",
        ["tenant_id", "provider", "model"],
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    Histogram = Any  # type: ignore[misc, assignment]
    OPERATION_DURATION_SECONDS = None
    STREAM_LAG_GAUGE = None
    PENDING_ENTRY_AGE_GAUGE = None
    BARRIER_AGE_GAUGE = None
    CIRCUIT_BREAKER_STATE_GAUGE = None
    REQUESTS_TOTAL = None
    DEGRADED_REQUESTS_TOTAL = None
    ACTIVE_SSE_CONNECTIONS_GAUGE = None
    LLM_TOKENS_COUNTER = None
    LLM_COST_COUNTER = None


def _record_observation(
    histogram: Histogram | None,
    service: str,
    operation: str,
    status: str,
    start: float,
) -> None:
    if not PROMETHEUS_AVAILABLE or histogram is None:
        return
    elapsed = time.perf_counter() - start
    histogram.labels(
        service=service,
        operation=operation,
        status=status,
    ).observe(elapsed)


@contextmanager
def observe_duration(
    service: str,
    operation: str,
    histogram: Histogram | None = OPERATION_DURATION_SECONDS,
    status: str = "ok",
):
    """Synchronous context manager to record duration in seconds."""
    start = time.perf_counter()
    current_status = status
    try:
        yield
    except Exception:
        current_status = "error"
        raise
    finally:
        _record_observation(histogram, service, operation, current_status, start)


@asynccontextmanager
async def observe_duration_async(
    service: str,
    operation: str,
    histogram: Histogram | None = OPERATION_DURATION_SECONDS,
    status: str = "ok",
):
    """Async context manager to record duration in seconds."""
    start = time.perf_counter()
    current_status = status
    try:
        yield
    except Exception:
        current_status = "error"
        raise
    finally:
        _record_observation(histogram, service, operation, current_status, start)


def record_llm_metrics(
    tenant_id: str,
    provider: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
    cost_estimate: float,
):
    """Record LLM token usage and cost metrics with strict cardinality control."""
    if not PROMETHEUS_AVAILABLE:
        return
    clean_tenant = tenant_id[:50] if tenant_id else "default"
    clean_provider = provider[:30] if provider else "unknown"
    clean_model = model[:50] if model else "unknown"
    LLM_TOKENS_COUNTER.labels(
        tenant_id=clean_tenant,
        provider=clean_provider,
        model=clean_model,
        type="prompt",
    ).inc(prompt_tokens)
    LLM_TOKENS_COUNTER.labels(
        tenant_id=clean_tenant,
        provider=clean_provider,
        model=clean_model,
        type="completion",
    ).inc(completion_tokens)
    LLM_TOKENS_COUNTER.labels(
        tenant_id=clean_tenant, provider=clean_provider, model=clean_model, type="total"
    ).inc(total_tokens)
    LLM_COST_COUNTER.labels(
        tenant_id=clean_tenant, provider=clean_provider, model=clean_model
    ).inc(cost_estimate)


def update_breaker_metric(provider_name: str, state_str: str):
    """Record circuit breaker state metric (0=CLOSED, 1=HALF_OPEN, 2=OPEN)."""
    if not PROMETHEUS_AVAILABLE:
        return
    val_map = {"CLOSED": 0, "HALF_OPEN": 1, "OPEN": 2}
    val = val_map.get(state_str.upper(), 0)
    CIRCUIT_BREAKER_STATE_GAUGE.labels(provider=provider_name).set(val)


def get_metrics_payload() -> tuple[bytes, str]:
    """Returns Prometheus metrics payload and content type."""
    if PROMETHEUS_AVAILABLE:
        return generate_latest(), CONTENT_TYPE_LATEST
    return b"# Prometheus client not available\n", "text/plain"
