"""
Version 2 REST API Transport Schemas.
"""

from typing import Any, Optional

from pydantic import BaseModel, Field


class TripPlanRequestV2(BaseModel):
    query: str = Field(default="", max_length=2000)
    destination: Optional["str"] = None
    departure_city: Optional["str"] = None
    start_date: Optional["str"] = None
    end_date: Optional["str"] = None


class TripResponseV2(BaseModel):
    id: str
    correlation_id: str
    status: str
    query: str
    summary: Optional["str"] = None
    itinerary_details: dict[str, Any] | None = None
    providers_degraded: dict[str, bool] = Field(default_factory=dict)
    created_at: str
