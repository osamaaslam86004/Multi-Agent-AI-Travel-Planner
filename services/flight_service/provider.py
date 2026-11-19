"""
Flight Provider with AviationStack REST / MCP, Redis Caching, and Resilience.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
from typing import Any

import redis.asyncio as aioredis
from langchain_mcp_adapters.client import MultiServerMCPClient

from services.common.resilience import CircuitBreaker, resilient_execute
from services.common.schemas import ProviderResult

logger = logging.getLogger("travelbrain.flight_service")

AVIATIONSTACK_API_KEY = (
    os.getenv("AVIATION_STACK_API_KEY") or os.getenv("AVIATIONSTACK_API_KEY") or ""
)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/1")
AVIATIONSTACK_MCP_COMMAND = os.getenv("AVIATIONSTACK_MCP_COMMAND", "aviationstack-mcp")

flight_breaker = CircuitBreaker("AviationStackBreaker", fail_max=4, reset_timeout=30.0)
flight_mcp_breaker = CircuitBreaker(
    "AviationStackMCPBreaker", fail_max=3, reset_timeout=20.0
)

APPROVED_FLIGHT_TOOLS = {
    "search_flights",
    "get_flight_status",
    "get_airport_info",
    "get_airline_info",
    "flight_search",
    "search_flight",
    "search",
}


class FlightProvider:
    """Manages flight lookup, caching, MCP, and heuristic fallback."""

    def __init__(self, redis_url: str = REDIS_URL):
        self.redis_url = redis_url
        self._redis: aioredis.Redis | None = None
        self._mcp_client: MultiServerMCPClient | None = None

    async def get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(
                self.redis_url, encoding="utf-8", decode_responses=True
            )
        return self._redis

    async def get_mcp_client(self) -> MultiServerMCPClient:
        if self._mcp_client is None:
            cmd = AVIATIONSTACK_MCP_COMMAND
            args_env = os.getenv("AVIATIONSTACK_MCP_ARGS", "")
            args = args_env.split() if args_env else []
            server_config = {
                "aviationstack": {
                    "command": cmd,
                    "args": args,
                    "transport": "stdio",
                    "env": {"AVIATION_STACK_API_KEY": AVIATIONSTACK_API_KEY},
                }
            }
            self._mcp_client = MultiServerMCPClient(server_config)
        return self._mcp_client

    async def close(self) -> None:
        if self._mcp_client is not None:
            for method in ("close", "aclose"):
                if hasattr(self._mcp_client, method):
                    try:
                        res = getattr(self._mcp_client, method)()
                        if asyncio.iscoroutine(res):
                            await res
                    except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
                        logger.warning("Error closing MCP client: %s", exc)
                    break
            self._mcp_client = None
        if self._redis is not None:
            try:
                await self._redis.close()
            except (aioredis.RedisError, OSError, RuntimeError) as exc:
                logger.debug("Ignoring Redis close error during shutdown: %s", exc)
            self._redis = None

    def _cache_key(
        self,
        query: str,
        departure_city: str | None = None,
        destination: str | None = None,
    ) -> str:
        raw = f"{query.strip().lower()}:{departure_city or ''}:{destination or ''}"
        h = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return f"flight:cache:{h}"

    async def search_flights(
        self,
        query: str,
        departure_city: str | None = None,
        destination: str | None = None,
        dates: str | None = None,
    ) -> ProviderResult:
        """High-level flight search with caching and circuit-broken execution."""
        redis = await self.get_redis()
        cache_key = self._cache_key(query, departure_city, destination)
        cached_data = await redis.get(cache_key)
        if cached_data:
            logger.info("Flight cache hit for query: '%s'", query)
            data_dict = json.loads(cached_data)
            return ProviderResult(**data_dict)

        results: ProviderResult = await resilient_execute(
            breaker=flight_breaker,
            primary_func=self._fetch_flights,
            fallback_func=self._fallback_flights,
            query=query,
            departure_city=departure_city,
            destination=destination,
            dates=dates,
        )

        # Cache discipline: Do not cache degraded fallback results for long TTL
        if not results.degraded:
            await redis.setex(cache_key, 86400, json.dumps(results.model_dump()))
        else:
            await redis.setex(cache_key, 60, json.dumps(results.model_dump()))

        return results

    async def _fetch_flights(
        self,
        query: str,
        departure_city: str | None = None,
        destination: str | None = None,
        dates: str | None = None,
    ) -> ProviderResult:
        """Try the AviationStack MCP."""
        errors: list[str] = []
        try:
            text = await flight_mcp_breaker.call(
                self._fetch_aviationstack_mcp,
                query=query,
                departure_city=departure_city,
                destination=destination,
            )
            if text and text.strip():
                return ProviderResult(
                    text=text, source="aviationstack_mcp", degraded=False
                )
            raise RuntimeError("AviationStack MCP returned empty output")

        except (TimeoutError, OSError, RuntimeError, ValueError) as exc:
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

    async def _fetch_aviationstack_mcp(
        self,
        query: str,
        departure_city: str | None = None,
        destination: str | None = None,
    ) -> str:
        """Discover AviationStack tools and invoke a flight-related tool."""
        if not AVIATIONSTACK_API_KEY:
            raise ValueError("AVIATION_STACK_API_KEY not configured")

        search_target = f"{departure_city or ''} to {destination or query}".strip()

        async with asyncio.timeout(10.0):
            client = await self.get_mcp_client()
            tools = await client.get_tools()
            if not tools:
                raise RuntimeError("No tools discovered from AviationStack MCP")

            matching = [
                tool
                for tool in tools
                if getattr(tool, "name", "").lower() in APPROVED_FLIGHT_TOOLS
            ]
            if not matching:
                matching = [
                    tool
                    for tool in tools
                    if any(
                        kw in getattr(tool, "name", "").lower()
                        for kw in ("flight", "airline", "schedule", "airport")
                    )
                ]
            if not matching:
                raise RuntimeError(
                    "No approved flight tool found in allowlist. Discovered: "
                    + ", ".join(getattr(t, "name", "?") for t in tools)
                )

            tool = matching[0]
            args = self._build_flight_tool_args(tool, search_target)
            output = await tool.ainvoke(args)
            normalized = self._normalize_mcp_output(output)
            if not normalized:
                raise RuntimeError(
                    f"MCP tool '{getattr(tool, 'name', '')}' returned empty data"
                )
            return normalized

    async def _fallback_flights(
        self,
        query: str,
        departure_city: str | None = None,
        destination: str | None = None,
        dates: str | None = None,
    ) -> ProviderResult:
        """Graceful fallback when upstream APIs/MCP are unavailable."""
        dep = departure_city or "origin"
        dest = destination or query
        text = (
            f"Flight Information for '{dep}' to '{dest}':\n"
            f"- Status: Real-time flight data unavailable (degraded fallback).\n"
            f"- Note: Flight schedules and live prices could not be fetched from upstream providers."
        )
        return ProviderResult(text=text, source="fallback", degraded=True)
