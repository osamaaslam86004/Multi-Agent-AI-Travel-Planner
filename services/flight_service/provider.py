"""
Flight Provider with AviationStack MCP / REST Integration, Redis Caching, and Resilience.
"""

import hashlib
import json
import logging
import os
from typing import Any

import httpx
import redis.asyncio as aioredis

from services.common.resilience import CircuitBreaker, resilient_execute

logger = logging.getLogger("travelbrain.flight_service")

AVIATIONSTACK_API_KEY = os.getenv("AVIATIONSTACK_API_KEY", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/1")

flight_breaker = CircuitBreaker("AviationStackBreaker", fail_max=4, reset_timeout=30.0)


class FlightProvider:
    """Manages flight lookups, Redis caching, circuit breaker, and heuristic fallbacks."""

    def __init__(self, redis_url: str = REDIS_URL):
        self.redis_url = redis_url
        self._redis: aioredis.Redis | None = None

    async def get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(
                self.redis_url, encoding="utf-8", decode_responses=True
            )
        return self._redis

    def _cache_key(self, query: str) -> str:
        h = hashlib.sha256(query.strip().lower().encode()).hexdigest()[:16]
        return f"flight:cache:{h}"

    async def search_flights(self, query: str) -> dict[str, Any]:
        """High-level flight search with caching and circuit-broken execution."""
        r = await self.get_redis()
        cache_key = self._cache_key(query)

        # Check Cache
        cached_data = await r.get(cache_key)
        if cached_data:
            logger.info(f"Flight cache hit for query: '{query}'")
            return {"results": json.loads(cached_data), "cached": True}

        # Resilient Execution
        results = await resilient_execute(
            breaker=flight_breaker,
            primary_func=self._fetch_aviationstack,
            fallback_func=self._fallback_flights,
            query=query,
        )

        # Store in Redis Cache (24-hour TTL)
        await r.setex(cache_key, 86400, json.dumps(results))
        return {"results": results, "cached": False}

    async def _fetch_aviationstack(self, query: str) -> str:
        """Call AviationStack API when key is configured."""
        if not AVIATIONSTACK_API_KEY:
            # Trigger fallback immediately if no key provided
            raise ValueError("AviationStack API key not configured")

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                "http://api.aviationstack.com/v1/flights",
                params={"access_key": AVIATIONSTACK_API_KEY, "limit": 5},
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"AviationStack HTTP {resp.status_code}: {resp.text}"
                )
            data = resp.json()
            return f"Live AviationStack flights found: {len(data.get('data', []))} records available."

    async def _fallback_flights(self, query: str) -> str:
        """Graceful fallback heuristic when upstream API is unavailable or unconfigured."""
        return (
            f"Flight Guidance for '{query}':\n"
            f"- Recommended Route: Direct or 1-stop connection via major international hubs.\n"
            f"- Estimated Economy Airfare: $450 - $950 round-trip.\n"
            f"- Recommended Booking Window: 4 to 8 weeks in advance for best fares.\n"
            f"- Common Carriers: Major international and partner alliance airlines."
        )
