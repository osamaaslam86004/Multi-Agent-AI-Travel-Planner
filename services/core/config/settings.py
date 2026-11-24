"""
Unified Centralized Settings Aggregator.
Combines domain settings with backward-compatible legacy property access.
"""
from pydantic import BaseModel, Field

from services.core.config.app import ApplicationSettings
from services.core.config.auth import AuthSettings
from services.core.config.db import DatabaseSettings
from services.core.config.deployment import DeploymentSettings
from services.core.config.feature_flags import FeatureFlagSettings
from services.core.config.llm import LLMSettings
from services.core.config.mcp import MCPSettings
from services.core.config.observability import ObservabilitySettings
from services.core.config.rate_limits import RateLimitSettings
from services.core.config.redis import RedisSettings
from services.core.config.security import SecuritySettings
from services.core.config.validators import validate_profile_settings


class Settings(BaseModel):
    model_config = {"arbitrary_types_allowed": True}
    app: ApplicationSettings = Field(default_factory=ApplicationSettings.load)
    auth: AuthSettings = Field(default_factory=AuthSettings.load)
    db: DatabaseSettings = Field(default_factory=DatabaseSettings.load)
    redis: RedisSettings = Field(default_factory=RedisSettings.load)
    llm: LLMSettings = Field(default_factory=LLMSettings.load)
    mcp: MCPSettings = Field(default_factory=MCPSettings.load)
    observability: ObservabilitySettings = Field(
        default_factory=ObservabilitySettings.load
    )
    security: SecuritySettings = Field(default_factory=SecuritySettings.load)
    rate_limits: RateLimitSettings = Field(default_factory=RateLimitSettings.load)
    deployment: DeploymentSettings = Field(default_factory=DeploymentSettings.load)
    feature_flags: FeatureFlagSettings = Field(default_factory=FeatureFlagSettings.load)
    # Legacy Backward-Compatible Alias Properties
    @property
    def ENVIRONMENT(self) -> str:
        return self.app.environment
    @property
    def PORT(self) -> int:
        return self.app.port
    @property
    def REDIS_URL(self) -> str:
        return self.redis.url
    @property
    def REDIS_CACHE_URL(self) -> str:
        return self.redis.cache_url
    @property
    def REDIS_PASSWORD(self) -> str | None:
        return self.redis.password or ""
    @property
    def POSTGRES_HOST(self) -> str:
        return self.db.host
    @property
    def POSTGRES_PORT(self) -> int:
        return self.db.port
    @property
    def POSTGRES_DB(self) -> str:
        return self.db.db_name
    @property
    def POSTGRES_USER(self) -> str:
        return self.db.user
    @property
    def POSTGRES_PASSWORD(self) -> str:
        return self.db.password
    @property
    def AUTH_SERVICE_URL(self) -> str:
        return self.auth.auth_service_url
    @property
    def AUTH_SERVICE_JWKS_URL(self) -> str:
        return self.auth.auth_service_jwks_url
    @property
    def JWT_ISSUER(self) -> str:
        return self.auth.jwt_issuer
    @property
    def JWT_AUDIENCE(self) -> str:
        return self.auth.jwt_audience
_settings_instance: Settings | None = None
def get_settings(force_reload: bool = False) -> Settings:
    global _settings_instance
    if _settings_instance is None or force_reload:
        settings = Settings()
        validate_profile_settings(settings)
        _settings_instance = settings
    return _settings_instance
def reload_settings() -> Settings:
    return get_settings(force_reload=True)