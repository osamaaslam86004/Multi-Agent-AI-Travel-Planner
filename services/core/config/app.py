"""
Application Domain Settings.
"""

from pydantic import Field

from services.core.config.base import BaseDomainSettings


class ApplicationSettings(BaseDomainSettings):
    app_name: str = "TravelBrain AI Enterprise"
    app_version: str = "2.0.0"
    environment: str = Field(
        default="development", description="development, staging, or production"
    )
    debug: bool = False
    port: int = 8000
    api_prefix: str = "/api/v1"
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])
    request_timeout_seconds: float = 30.0
    retry_max_attempts: int = 3
    retry_backoff_factor: float = 0.5

    @classmethod
    def load(cls) -> "ApplicationSettings":
        aliases = {
            "environment": "ENVIRONMENT",
            "port": "PORT",
            "debug": "DEBUG",
        }
        return cls.load_from_env(prefix="APP", aliases=aliases)
