"""
Versioned Event and Stream Payload Contracts for Event-Driven Architecture.
Supports CloudEvents v1.0 specification with explicit event_versioning.
"""

import uuid
from datetime import UTC, datetime
from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class CloudEventV1(BaseModel, Generic[T]):
    specversion: str = "1.0"
    event_version: str = "1.0.0"
    id: str = Field(default_factory=lambda: f"evt_{uuid.uuid4().hex}")
    source: str
    type: str
    time: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    datacontenttype: str = "application/json"
    subject: str | None = None
    dataschema: str | None = "https://travelbrain.ai/schemas/v1"
    traceparent: str | None = None
    data: T


# Domain Payloads
class PlanningInitiatedPayload(BaseModel):
    correlation_id: str
    user_id: str
    tenant_id: str = "default"
    user_query: str
    destination: Optional["str"] = None
    departure_city: Optional["str"] = None
    start_date: Optional["str"] = None
    end_date: Optional["str"] = None
    dates: Optional["str"] = None
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class FlightResultPayload(BaseModel):
    correlation_id: str
    user_id: str = "unknown"
    tenant_id: str = "default"
    user_query: str = ""
    success: bool
    results: str
    source: str = "unknown"
    degraded: bool = False
    cached: bool = False
    error: Optional["str"] = None


class HotelResultPayload(BaseModel):
    correlation_id: str
    user_id: str = "unknown"
    tenant_id: str = "default"
    user_query: str = ""
    success: bool
    results: str
    source: str = "unknown"
    degraded: bool = False
    cached: bool = False
    error: Optional["str"] = None


class WeatherResultPayload(BaseModel):
    correlation_id: str
    user_id: str = "unknown"
    tenant_id: str = "default"
    user_query: str = ""
    success: bool
    results: str
    source: str = "unknown"
    degraded: bool = False
    cached: bool = False
    error: Optional["str"] = None


class SynthesisCompletedPayload(BaseModel):
    correlation_id: str
    user_id: str
    tenant_id: str = "default"
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


class LLMUsagePayload(BaseModel):
    tenant_id: str
    user_id: str
    correlation_id: str
    provider: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    latency_ms: float
    cost_estimate: float
