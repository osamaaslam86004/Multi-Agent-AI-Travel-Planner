"""
Hotel Provider with Tavily Search Integration, Redis Caching, and Fallback Resilience.
"""

import hashlib
import json
import logging
import os
from typing import Any

import redis.asyncio as aioredis
from tavily import TavilyClient

from services.common.resilience import CircuitBreaker, resilient_execute

logger = logging.getLogger("travelbrain.hotel_service")

TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/2")

hotel_breaker = CircuitBreaker("TavilyHotelBreaker", fail_max=4, reset_timeout=30.0)


class HotelProvider:
    """Manages accommodation searches, Tavily queries, and heuristic fallbacks."""

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
        return f"hotel:cache:{h}"

    async def search_hotels(self, query: str) -> dict[str, Any]:
        """High-level hotel search with caching and circuit-broken execution."""
        r = await self.get_redis()
        cache_key = self._cache_key(query)

        cached_data = await r.get(cache_key)
        if cached_data:
            logger.info(f"Hotel cache hit for query: '{query}'")
            return {"results": json.loads(cached_data), "cached": True}

        results = await resilient_execute(
            breaker=hotel_breaker,
            primary_func=self._fetch_tavily_hotels,
            fallback_func=self._fallback_hotels,
            query=query,
        )

        # Store in Redis Cache (12-hour TTL)
        await r.setex(cache_key, 43200, json.dumps(results))
        return {"results": results, "cached": False}

    async def _fetch_tavily_hotels(self, query: str) -> str:
        """Call Tavily search API for curated hotels."""
        if not TAVILY_API_KEY:
            raise ValueError("Tavily API key not configured")

        client = TavilyClient(api_key=TAVILY_API_KEY)
        response = client.search(
            query=f"Best recommended hotels accommodations in {query}",
            search_depth="advanced",
            max_results=5,
        )
        snippets = [
            f"- {item.get('title')}: {item.get('content')}"
            for item in response.get("results", [])
        ]
        return "\n".join(snippets) if snippets else "No hotels retrieved."

    async def _fallback_hotels(self, query: str) -> str:
        """Fallback accommodation recommendations when Tavily is unavailable."""
        return (
            f"Hotel Recommendations for '{query}':\n"
            f"1. Luxury: 5-Star City Center Grand Hotel ($300 - $550/night) - Full amenities, spa, central location.\n"
            f"2. Boutique / Mid-Range: Modern Historic District Hotel ($140 - $220/night) - High walkability, breakfast included.\n"
            f"3. Value: Metro-adjacent Boutique Pod/Aparthotel ($70 - $110/night) - Clean, fast Wi-Fi, transit access."
        )
