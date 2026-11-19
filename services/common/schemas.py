"""
Shared CloudEvents schemas and Pydantic models for inter-service communication.
"""

import uuid
from datetime import UTC, datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class CloudEvent(BaseModel, Generic[T]):
    """CloudEvents v1.0 specification compliant envelope."""

    specversion: str = "1.0"
    id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex}")
    source: str
    type: str
    time: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    datacontenttype: str = "application/json"
    traceparent: str | None = None
    data: T


class ProviderResult(BaseModel):
    """Explicit result returned by domain providers indicating source and degradation status."""

    text: str
    source: str = "unknown"
    degraded: bool = False


# Domain Payloads
class PlanningInitiatedPayload(BaseModel):
    correlation_id: str
    user_id: str
    tenant_id: str = "default"
    user_query: str
    destination: str | None = None
    departure_city: str | None = None
    start_date: str | None = None
    end_date: str | None = None
    dates: str | None = None
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class FlightResultPayload(BaseModel):
    correlation_id: str
    success: bool
    results: str
    source: str = "unknown"
    degraded: bool = False
    cached: bool = False
    error: str | None = None


class HotelResultPayload(BaseModel):
    correlation_id: str
    success: bool
    results: str
    source: str = "unknown"
    degraded: bool = False
    cached: bool = False
    error: str | None = None


class WeatherResultPayload(BaseModel):
    correlation_id: str
    success: bool
    results: str
    source: str = "unknown"
    degraded: bool = False
    cached: bool = False
    error: str | None = None


class SynthesisCompletedPayload(BaseModel):
    correlation_id: str
    user_id: str
    user_query: str
    flight_results: str
    hotel_results: str
    weather_results: str
    itinerary: str
    final_response: str
    flight_degraded: bool = False
    hotel_degraded: bool = False
    weather_degraded: bool = False
    llm_calls: int = 1
    completed_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class StreamProgressUpdate(BaseModel):
    correlation_id: str
    stage: str
    message: str
    percentage: int
    payload: dict[str, Any] | None = None


class LLMResult(BaseModel):
    """Standardized result returned by all LLM providers."""

    content: str
    provider_name: str
    model_name: str
    token_usage: dict[str, int] = Field(
        default_factory=lambda: {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        }
    )
    latency_ms: float = 0.0
    structured_data: dict[str, Any] | None = None
