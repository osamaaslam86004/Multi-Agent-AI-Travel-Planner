"""
Version 1 REST API Transport Schemas.
"""

from typing import Optional

from pydantic import BaseModel, Field


class TripPlanRequestV1(BaseModel):
    message: str = Field(
        default="", max_length=2000, description="User query for trip planning"
    )


class TripResponseV1(BaseModel):
    trip_id: str
    tenant_id: str
    user_id: str
    correlation_id: str
    user_query: str
    status: str
    itinerary: Optional["str"] = None
    final_response: Optional["str"] = None
    flight_results: Optional["str"] = None
    hotel_results: Optional["str"] = None
    weather_results: Optional["str"] = None
    flight_degraded: bool = False
    hotel_degraded: bool = False
    weather_degraded: bool = False
    created_at: str
    updated_at: str


class AuthLoginRequestV1(BaseModel):
    email: str
    password: str


class TokenResponseV1(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
