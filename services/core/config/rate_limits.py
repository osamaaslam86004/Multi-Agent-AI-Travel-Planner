"""
Rate Limiting Domain Settings.
"""

from services.core.config.base import BaseDomainSettings


class RateLimitSettings(BaseDomainSettings):
    global_rate_limit_per_minute: int = 120
    auth_rate_limit_per_minute: int = 30
    sse_max_connections_per_user: int = 5
    rate_limit_redis_prefix: str = "tb:ratelimit:"

    @classmethod
    def load(cls) -> "RateLimitSettings":
        aliases = {
            "global_rate_limit_per_minute": "GLOBAL_RATE_LIMIT",
            "auth_rate_limit_per_minute": "AUTH_RATE_LIMIT",
        }
        return cls.load_from_env(prefix="RATELIMIT", aliases=aliases)
