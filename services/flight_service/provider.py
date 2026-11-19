"""
Flight Provider with AviationStack REST / MCP, Redis Caching, and Resilience.
"""

import hashlib
import json
import logging
import os
import re
from typing import Any

import redis.asyncio as aioredis
from langchain_mcp_adapters.client import MultiServerMCPClient

from services.common.resilience import CircuitBreaker, resilient_execute

logger = logging.getLogger("travelbrain.flight_service")

AVIATIONSTACK_API_KEY = (
    os.getenv("AVIATION_STACK_API_KEY") or os.getenv("AVIATIONSTACK_API_KEY") or ""
)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/1")
AVIATIONSTACK_MCP_COMMAND = os.getenv("AVIATIONSTACK_MCP_COMMAND", "uvx")
AVIATIONSTACK_MCP_PACKAGE = os.getenv("AVIATIONSTACK_MCP_PACKAGE", "aviationstack-mcp")

flight_breaker = CircuitBreaker("AviationStackBreaker", fail_max=4, reset_timeout=30.0)
flight_mcp_breaker = CircuitBreaker(
    "AviationStackMCPBreaker", fail_max=3, reset_timeout=20.0
)


class FlightProvider:
    """Manages flight lookup, caching, MCP, and heuristic fallback."""

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
        redis = await self.get_redis()
        cache_key = self._cache_key(query)

        cached_data = await redis.get(cache_key)
        if cached_data:
            logger.info("Flight cache hit for query: '%s'", query)
            return {"results": json.loads(cached_data), "cached": True}

        results = await resilient_execute(
            breaker=flight_breaker,
            primary_func=self._fetch_flights,
            fallback_func=self._fallback_flights,
            query=query,
        )

        await redis.setex(cache_key, 86400, json.dumps(results))
        return {"results": results, "cached": False}

    async def _fetch_flights(self, query: str) -> str:
        """Try the AviationStack MCP."""
        errors: list[str] = []

        try:
            result = await flight_mcp_breaker.call(
                self._fetch_aviationstack_mcp, query=query
            )
            if result and result.strip():
                return result
            raise RuntimeError("AviationStack MCP returned empty output")
        except Exception as exc:
            errors.append(f"MCP: {exc}")
            logger.warning("AviationStack MCP failed: %s", exc)

        raise RuntimeError("Flight provider tiers exhausted: " + "; ".join(errors))

    @staticmethod
    def _tool_fields(tool: Any) -> dict[str, Any]:
        schema = getattr(tool, "args_schema", None)
        if not schema:
            return {}
        return (
            getattr(schema, "model_fields", None)
            or getattr(schema, "__fields__", None)
            or {}
        )

    @staticmethod
    def _build_flight_tool_args(tool: Any, query: str) -> dict[str, Any]:
        """Build tool inputs based on its dynamically discovered schema."""
        fields = FlightProvider._tool_fields(tool)
        if not fields:
            return {"query": query}

        args: dict[str, Any] = {}
        query_fields = (
            "query",
            "search_query",
            "keywords",
            "search",
            "flight",
            "flight_iata",
            "flight_number",
            "airline_name",
            "airline",
            "airport_iata_code",
            "airport",
            "iata_code",
        )
        for field in query_fields:
            if field in fields:
                args[field] = query
                break

        # Populate known required fields only when inferable from the query.
        upper = query.upper()
        flight_match = re.search(r"\b([A-Z]{2,3}\d{1,4})\b", upper)
        airport_match = re.search(r"\b([A-Z]{3})\b", upper)

        for field in fields:
            field_lower = field.lower()
            if field in args:
                continue
            if field_lower in ("flight_iata", "flight_number") and flight_match:
                args[field] = flight_match.group(1)
            elif field_lower in ("airport_iata_code", "iata_code") and airport_match:
                args[field] = airport_match.group(1)
            elif field_lower in ("search", "query", "keywords", "search_query"):
                args[field] = query

        return args

    @staticmethod
    def _normalize_mcp_output(output: Any) -> str:
        """Convert MCP response shapes into readable text."""
        if output is None:
            return ""
        if isinstance(output, str):
            return output.strip()
        if isinstance(output, (int, float, bool)):
            return str(output)
        if isinstance(output, dict):
            for key in ("text", "content", "result", "data", "output"):
                if key in output:
                    normalized = FlightProvider._normalize_mcp_output(output[key])
                    if normalized:
                        return normalized
            return json.dumps(output, ensure_ascii=False, default=str)
        if isinstance(output, list):
            parts = [FlightProvider._normalize_mcp_output(item) for item in output]
            return "\n".join(part for part in parts if part)
        if hasattr(output, "content"):
            return FlightProvider._normalize_mcp_output(output.content)
        if hasattr(output, "text"):
            return FlightProvider._normalize_mcp_output(output.text)
        return str(output)

    async def _fetch_aviationstack_mcp(self, query: str) -> str:
        """Discover AviationStack tools and invoke a flight-related tool."""
        if not AVIATIONSTACK_API_KEY:
            raise ValueError("AVIATION_STACK_API_KEY not configured")

        server_config = {
            "aviationstack": {
                "command": AVIATIONSTACK_MCP_COMMAND,
                "args": ["--from", AVIATIONSTACK_MCP_PACKAGE, "aviationstack-mcp"],
                "transport": "stdio",
                "env": {"AVIATION_STACK_API_KEY": AVIATIONSTACK_API_KEY},
            }
        }

        async with MultiServerMCPClient(server_config) as client:
            tools = client.get_tools()
            if not tools:
                raise RuntimeError("No tools discovered from AviationStack MCP")

            preferred = [
                tool
                for tool in tools
                if any(
                    word in getattr(tool, "name", "").lower()
                    for word in ("flight", "airline", "schedule", "airport")
                )
            ]
            if not preferred:
                raise RuntimeError(
                    "No flight-related tools discovered. Available: "
                    + ", ".join(getattr(t, "name", "?") for t in tools)
                )

            # Prefer tools with a query-like argument; otherwise select the
            # first flight-related tool and let schema adaptation handle it.
            tool = next(
                (
                    candidate
                    for candidate in preferred
                    if any(
                        field in self._tool_fields(candidate)
                        for field in (
                            "query",
                            "search_query",
                            "keywords",
                            "flight_iata",
                            "airline_name",
                        )
                    )
                ),
                preferred[0],
            )
            args = self._build_flight_tool_args(tool, query)
            output = await tool.ainvoke(args)
            normalized = self._normalize_mcp_output(output)
            if not normalized:
                raise RuntimeError(f"MCP tool '{tool.name}' returned empty data")
            return normalized

    async def _fallback_flights(self, query: str) -> str:
        """Graceful fallback when upstream APIs/MCP are unavailable."""
        return (
            f"Flight Guidance for '{query}':\n"
            "- Recommended Route: Direct or 1-stop connection via major international hubs.\n"
            "- Estimated Economy Airfare: $450 - $950 round-trip.\n"
            "- Recommended Booking Window: 4 to 8 weeks in advance for best fares.\n"
            "- Common Carriers: Major international and partner alliance airlines."
        )
