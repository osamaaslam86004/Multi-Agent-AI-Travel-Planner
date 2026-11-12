# src/config/settings.py
import os
from functools import lru_cache
from typing import Literal

import certifi
from pydantic import BaseModel, Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Corporate / secure network CA bundle fallback
os.environ["SSL_CERT_FILE"] = certifi.where()
os.environ["REQUESTS_CA_BUNDLE"] = certifi.where()


class AppConfig(BaseModel):
    name: str = "TravelBrain AI"
    description: str = "LangGraph Multi-Agent Travel Planner with FastAPI Frontend"
    version: str = "1.0.0"
    env: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    api_v1_prefix: str = "/api"


class SecurityConfig(BaseModel):
    session_cookie_name: str = "travelbrain_session"
    session_ttl_seconds: int = 43200  # 12 hours
    cors_origins: list[str] = Field(default_factory=list)
    cookie_samesite: Literal["lax", "strict", "none"] = "lax"
    cookie_secure: bool = False


class DatabaseConfig(BaseModel):
    url: str = Field(..., description="PostgreSQL database connection string")
    pool_size: int = 20
    max_overflow: int = 10

    @field_validator("url")
    @classmethod
    def normalize_database_url(cls, v: str) -> str:
        """Enforces sslmode=require for managed cloud PostgreSQL providers."""
        if v and "sslmode=" not in v:
            separator = "&" if "?" in v else "?"
            v = f"{v}{separator}sslmode=require"
        return v


class RedisConfig(BaseModel):
    url: str | None = Field(default=None, description="Redis cluster connection URL")
    enabled: bool = True
    reconnect_seconds: int = int(os.getenv("CACHE_RECONNECT_SECONDS", "60"))
    key_prefix: str = "travelbrain"
    ttl_airports: int = 7 * 24 * 3600
    ttl_airlines: int = 7 * 24 * 3600
    ttl_hotels: int = 6 * 3600
    ttl_weather: int = 600
    ttl_forecast: int = 3600
    ttl_destination: int = 24 * 3600


class LLMConfig(BaseModel):
    groq_api_key: SecretStr = Field(..., description="Groq API Key for agent execution")
    model: str = Field(
        default="openai/gpt-oss-20b", description="Groq Model Identifier"
    )

    @field_validator("groq_api_key")
    @classmethod
    def validate_groq_api_key(cls, v: SecretStr) -> SecretStr:
        raw_key = v.get_secret_value().strip()
        if not raw_key or len(raw_key) < 5:
            raise ValueError("GROQ_API_KEY appears invalid or too short.")
        return v


class ExternalAPIsConfig(BaseModel):
    tavily_api_key: SecretStr = Field(
        ..., description="Tavily API Key for hotel searches"
    )
    aviationstack_api_key: SecretStr = Field(
        ..., description="AviationStack API Key for flight data"
    )
    openweather_api_key: SecretStr = Field(
        ..., description="OpenWeather API Key for live weather/forecasts"
    )


class TruncationConfig(BaseModel):
    airport_data_char_limit: int = 3000
    airline_data_char_limit: int = 3000


class Settings(BaseSettings):
    app: AppConfig = Field(default_factory=AppConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    db: DatabaseConfig
    redis: RedisConfig = Field(default_factory=RedisConfig)
    llm: LLMConfig
    apis: ExternalAPIsConfig
    truncation: TruncationConfig = Field(default_factory=TruncationConfig)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        # Maps double underscore env vars (e.g., LLM__GROQ_API_KEY or DB__URL)
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
