"""
Centralized Feature Flag Evaluation Infrastructure.
"""

import logging

import redis.asyncio as aioredis

from services.core.config import get_settings
from services.shared.redis_client import get_redis_client

logger = logging.getLogger("travelbrain.core.feature_flags")


class FeatureFlagManager:
    """
    Centralized Feature Flag Evaluator supporting static settings and dynamic Redis overrides.
    """

    def __init__(self) -> None:
        self.settings = get_settings().feature_flags

    async def is_enabled(
        self,
        flag_name: str,
        tenant_id: str | None = None,
        user_id: str | None = None,
        default: bool = False,
    ) -> bool:
        if hasattr(self.settings, flag_name):
            val = getattr(self.settings, flag_name)
            if isinstance(val, bool):
                default = val
        try:
            redis_client = await get_redis_client()
            if redis_client:
                if tenant_id:
                    tenant_val = await redis_client.get(
                        f"tb:ff:tenant:{tenant_id}:{flag_name}"
                    )
                    if tenant_val is not None:
                        return tenant_val.lower() in ("true", "1", "yes", "on")
                global_val = await redis_client.get(f"tb:ff:global:{flag_name}")
                if global_val is not None:
                    return global_val.lower() in ("true", "1", "yes", "on")
        except (
            aioredis.RedisError,
            OSError,
            RuntimeError,
            TimeoutError,
            ValueError,
        ) as exc:
            logger.debug(f"Failed dynamic feature flag lookup for '{flag_name}': {exc}")
        return default


_feature_flag_manager = FeatureFlagManager()


def get_feature_flag_manager() -> FeatureFlagManager:
    return _feature_flag_manager
