"""
Standard API Response and Error Envelopes for TravelBrain AI Services.
"""

import uuid
from datetime import UTC, datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class ErrorDetail(BaseModel):
    code: str = Field(
        default="INTERNAL_ERROR", description="Machine-readable error code"
    )
    message: str = Field(
        default="An error occurred", description="Human-readable error description"
    )
    target: str | None = Field(
        default=None, description="Field or resource that caused error"
    )
    details: list[dict[str, Any]] | None = Field(
        default=None, description="Additional context or validation errors"
    )
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class ErrorResponse(BaseModel):
    success: bool = False
    error: ErrorDetail


class ApiResponse(BaseModel, Generic[T]):
    success: bool = True
    data: T | None = None
    error: ErrorDetail | None = None
    meta: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def success_response(
        cls, data: T, meta: dict[str, Any] | None = None
    ) -> "ApiResponse[T]":
        meta_dict = meta or {}
        if "request_id" not in meta_dict:
            meta_dict["request_id"] = f"req_{uuid.uuid4().hex[:12]}"
        return cls(success=True, data=data, error=None, meta=meta_dict)

    @classmethod
    def error_response(
        cls,
        code: str,
        message: str,
        target: str | None = None,
        details: list[dict[str, Any]] | None = None,
        meta: dict[str, Any] | None = None,
    ) -> "ApiResponse[T]":
        error = ErrorDetail(code=code, message=message, target=target, details=details)
        return cls(success=False, data=None, error=error, meta=meta or {})


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    size: int
    pages: int
