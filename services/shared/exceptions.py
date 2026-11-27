"""
Unified Exception Hierarchy and FastAPI Global Exception Handlers.
"""

import logging
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from services.contracts.envelopes import ApiResponse

logger = logging.getLogger("travelbrain.shared.exceptions")


class TravelBrainError(Exception):
    def __init__(
        self,
        message: str,
        code: str = "INTERNAL_ERROR",
        status_code: int = 500,
        details: Any = None,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details


class ConfigurationError(TravelBrainError):
    def __init__(self, message: str):
        super().__init__(message, code="CONFIG_ERROR", status_code=500)


class AuthenticationError(TravelBrainError):
    def __init__(
        self, message: str = "Authentication failed", code: str = "AUTH_UNAUTHORIZED"
    ):
        super().__init__(message, code=code, status_code=401)


class AuthorizationError(TravelBrainError):
    def __init__(
        self, message: str = "Permission denied", code: str = "AUTH_FORBIDDEN"
    ):
        super().__init__(message, code=code, status_code=403)


class NotFoundError(TravelBrainError):
    def __init__(self, message: str = "Resource not found", code: str = "NOT_FOUND"):
        super().__init__(message, code=code, status_code=404)


class RateLimitExceededError(TravelBrainError):
    def __init__(
        self, message: str = "Rate limit exceeded", code: str = "RATE_LIMIT_EXCEEDED"
    ):
        super().__init__(message, code=code, status_code=429)


class ServiceUnavailableError(TravelBrainError):
    def __init__(
        self, message: str = "Service unavailable", code: str = "SERVICE_UNAVAILABLE"
    ):
        super().__init__(message, code=code, status_code=530)


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(TravelBrainError)
    async def travelbrain_error_handler(
        request: Request, exc: TravelBrainError
    ) -> JSONResponse:
        logger.warning(
            f"Domain exception [{exc.code}] on {request.url.path}: {exc.message}"
        )
        envelope = ApiResponse.error_response(
            code=exc.code,
            message=exc.message,
            details=exc.details,
            meta={"path": request.url.path},
        )
        return JSONResponse(status_code=exc.status_code, content=envelope.model_dump())

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        logger.warning(f"Validation error on {request.url.path}: {exc.errors()}")
        envelope = ApiResponse.error_response(
            code="VALIDATION_ERROR",
            message="Request body or query parameters failed validation",
            details=exc.errors(),
            meta={"path": request.url.path},
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=envelope.model_dump(),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        logger.exception(f"Unhandled exception on {request.url.path}: {exc}")
        envelope = ApiResponse.error_response(
            code="INTERNAL_SERVER_ERROR",
            message="An unexpected server error occurred",
            meta={"path": request.url.path},
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=envelope.model_dump(),
        )
