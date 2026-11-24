"""
Redis Domain Settings.
"""
from pydantic import Field

from services.core.config.base import BaseDomainSettings


class RedisSettings(BaseDomainSettings):
    url: str = Field(
        default="redis://localhost:6379/0", description="Primary Redis broker URL"
    )
    cache_url: str = Field(
        default="redis://localhost:6379/1", description="Redis cache URL"
    )
    password: str | None = Field(default=None, description="Redis password")
    max_connections: int = 50
    socket_timeout_seconds: float = 5.0
    socket_connect_timeout_seconds: float = 5.0
    dlq_stream_name: str = "stream:travel:dlq"
    stream_maxlen: int = 10000
    @classmethod
    def load(cls) -> "RedisSettings":
        aliases = {
            "url": "REDIS_URL",
            "cache_url": "REDIS_CACHE_URL",
            "password": "REDIS_PASSWORD",
            "max_connections": "REDIS_MAX_CONNECTIONS",
        }
        return cls.load_from_env(prefix="REDIS", aliases=aliases)