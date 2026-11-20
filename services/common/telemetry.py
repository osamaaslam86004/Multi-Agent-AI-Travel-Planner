"""
OpenTelemetry and W3C Trace Context Utilities for Distributed Tracing.
"""

import logging
import random
import re
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Tracer

logger = logging.getLogger("travelbrain.telemetry")
# W3C traceparent regex: 00-{32 hex trace_id}-{16 hex parent_id}-{2 hex flags}
TRACEPARENT_REGEX = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


def generate_traceparent() -> str:
    """Generate a valid W3C traceparent header."""
    trace_id = f"{random.getrandbits(128):032x}"
    span_id = f"{random.getrandbits(64):016x}"
    trace_flags = "01"  # sampled
    return f"00-{trace_id}-{span_id}-{trace_flags}"


def extract_traceparent(headers: dict[str, Any]) -> str:
    """Extract or generate a W3C traceparent."""
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
    """Inject W3C traceparent into a dictionary/headers."""
    tp = traceparent or generate_traceparent()
    carrier["traceparent"] = tp
    return carrier


def get_tracer(service_name: str = "travelbrain") -> Tracer:
    """Returns an OpenTelemetry tracer for the specified service name."""
    return trace.get_tracer(service_name)
