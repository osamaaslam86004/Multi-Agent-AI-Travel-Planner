"""
FastAPI Dependency Injection Providers.
"""
import httpx
import redis.asyncio as aioredis

from services.core.config import Settings, get_settings
from services.shared.http_client import get_httpx_client
from services.shared.redis_client import get_redis_client


def get_settings_dep() -> Settings:
    return get_settings()
async def get_redis_dep() -> aioredis.Redis:
    return await get_redis_client()
async def get_http_client_dep() -> httpx.AsyncClient:
    return await get_httpx_client()