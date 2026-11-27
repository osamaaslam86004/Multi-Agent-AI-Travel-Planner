"""
Unified Redis Client Factory with Connection Pooling and Lifecycle Integration.
Gracefully handles environments where redis is optional.
"""

import logging
from typing import Any

try:
    import redis.asyncio as aioredis
except ImportError:
    aioredis = None
from services.core.config import get_settings
from services.core.lifecycle.teardown import get_teardown_registry

logger = logging.getLogger("travelbrain.shared.redis")
_redis_client: Any = None


async def get_redis_client() -> Any:
    global _redis_client
    if aioredis is None:
        logger.warning("redis package not installed; returning None for redis client.")
        return None
    if _redis_client is None:
        settings = get_settings()
        _redis_client = aioredis.from_url(
            settings.redis.url,
            password=settings.redis.password or None,
            max_connections=settings.redis.max_connections,
            socket_timeout=settings.redis.socket_timeout_seconds,
            socket_connect_timeout=settings.redis.socket_connect_timeout_seconds,
            encoding="utf-8",
            decode_responses=True,
        )
        logger.info(
            f"Initialized unified Redis client connection to {settings.redis.url}"
        )
        registry = get_teardown_registry()
        registry.register("redis_client", close_redis_client)
    return _redis_client


async def close_redis_client() -> None:
    global _redis_client
    if _redis_client is not None and aioredis is not None:
        try:
            await _redis_client.aclose()
            logger.info("Closed unified Redis client connection.")
        except Exception as exc:
            logger.error(f"Error closing Redis client: {exc}")
        finally:
            _redis_client = None
