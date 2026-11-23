"""
Weather Provider with OpenWeather API + MCP, Redis caching, and fallback resilience.
"""

import asyncio
import hashlib
import json
import logging
import os
from typing import Any

import redis.asyncio as aioredis

from services.common.resilience import CircuitBreaker, resilient_execute
from services.common.schemas import ProviderResult

logger = logging.getLogger("travelbrain.weather_service")
OPENWEATHER_API_KEY = os.getenv("OPENWEATHER_API_KEY", "")
REDIS_CACHE_URL = os.getenv(
    "REDIS_CACHE_URL", os.getenv("REDIS_URL", "redis://localhost:6379/3")
)
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
weather_breaker = CircuitBreaker("OpenWeatherBreaker", fail_max=4, reset_timeout=30.0)


class WeatherProvider:
    """Manages weather lookups, caching, MCP, and heuristic fallback."""

    def __init__(self, redis_url: str = REDIS_CACHE_URL):
        self._single_flight_locks: dict[str, asyncio.Lock] = {}
        self.redis_url = redis_url
        self._redis: Any = None
        self._mcp_client: Any = None

    async def get_redis(self) -> Any:
        if aioredis is None:
            return None
        if self._redis is None:
            self._redis = aioredis.from_url(
                self.redis_url,
                password=os.getenv("REDIS_PASSWORD", "") or None,
                encoding="utf-8",
                decode_responses=True,
            )
        return self._redis

    async def close(self) -> None:
        if self._redis is not None:
            try:
                await self._redis.close()
            except Exception as exc:
                logger.debug(f"Ignoring Redis close error during shutdown: {exc}")
            self._redis = None

    def _cache_key(
        self, city: str, dates: str | None = None, tenant_id: str = "default"
    ) -> str:
        dt = (dates or "").strip().lower()
        raw = f"{tenant_id}:{city.strip().lower()}:{dt}"
        h = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return f"weather:cache:{tenant_id}:{h}"

    async def get_weather(
        self,
        query: str,
        destination: str | None = None,
        dates: str | None = None,
        tenant_id: str = "default",
    ) -> ProviderResult:
        city = destination or query
        redis = await self.get_redis()
        cache_key = self._cache_key(city, dates, tenant_id)
        if redis:
            cached_data = await redis.get(cache_key)
            if cached_data:
                logger.info(
                    "Weather cache hit for key '%s' (tenant: %s)", cache_key, tenant_id
                )
                return ProviderResult(**json.loads(cached_data))
        if cache_key not in self._single_flight_locks:
            self._single_flight_locks[cache_key] = asyncio.Lock()
        async with self._single_flight_locks[cache_key]:
            if redis:
                cached_data = await redis.get(cache_key)
                if cached_data:
                    return ProviderResult(**json.loads(cached_data))
            results: ProviderResult = await resilient_execute(
                breaker=weather_breaker,
                primary_func=self._fallback_weather,
                fallback_func=self._fallback_weather,
                city=city,
                dates=dates,
            )
            if redis and not results.degraded:
                await redis.setex(cache_key, 21600, json.dumps(results.model_dump()))
            return results

    async def _fallback_weather(
        self, city: str, dates: str | None = None
    ) -> ProviderResult:
        text = (
            f"Weather Forecast for '{city}':\n"
            f"- Status: Live weather data unavailable (degraded fallback).\n"
            f"- Note: Real-time weather forecast could not be retrieved from upstream providers."
        )
        return ProviderResult(text=text, source="fallback", degraded=True)
