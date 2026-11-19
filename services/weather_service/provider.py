"""
Weather Provider with OpenWeather API + MCP, Redis caching, and fallback resilience.
MCP is attempted after direct API path fails or when configured.
"""

import asyncio
import hashlib
import json
import logging
import os
from typing import Any

import redis.asyncio as aioredis
from langchain_mcp_adapters.client import MultiServerMCPClient

from services.common.resilience import CircuitBreaker, resilient_execute
from services.common.schemas import ProviderResult

logger = logging.getLogger("travelbrain.weather_service")

OPENWEATHER_API_KEY = os.getenv("OPENWEATHER_API_KEY", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/3")
OPENWEATHER_MCP_COMMAND = os.getenv("OPENWEATHER_MCP_COMMAND", "openweather-mcp")

weather_breaker = CircuitBreaker("OpenWeatherBreaker", fail_max=4, reset_timeout=30.0)
weather_mcp_breaker = CircuitBreaker(
    "OpenWeatherMCPBreaker", fail_max=3, reset_timeout=20.0
)

APPROVED_WEATHER_TOOLS = {
    "get_current_weather",
    "get_weather_forecast",
    "get_weather",
    "current_weather",
    "weather_search",
}


class WeatherProvider:
    """Manages weather lookups, caching, MCP, and heuristic fallback."""

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
            cmd = OPENWEATHER_MCP_COMMAND
            args_env = os.getenv("OPENWEATHER_MCP_ARGS", "")
            args = args_env.split() if args_env else []
            server_config = {
                "openweather": {
                    "command": cmd,
                    "args": args,
                    "transport": "stdio",
                    "env": {"OPENWEATHER_API_KEY": OPENWEATHER_API_KEY},
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
                        logger.warning("Error closing weather MCP client: %s", exc)
                    break
            self._mcp_client = None
        if self._redis is not None:
            try:
                await self._redis.close()
            except (aioredis.RedisError, OSError, RuntimeError) as exc:
                logger.debug("Ignoring Redis close error during shutdown: %s", exc)
            self._redis = None

    def _cache_key(self, city: str) -> str:
        h = hashlib.sha256(city.strip().lower().encode()).hexdigest()[:16]
        return f"weather:cache:{h}"

    async def get_weather(
        self,
        query: str,
        destination: str | None = None,
        dates: str | None = None,
    ) -> ProviderResult:
        """High-level weather lookup using structured destination or query."""
        city = destination or query
        redis = await self.get_redis()
        cache_key = self._cache_key(city)
        cached_data = await redis.get(cache_key)
        if cached_data:
            logger.info("Weather cache hit for city: '%s'", city)
            return ProviderResult(**json.loads(cached_data))

        results: ProviderResult = await resilient_execute(
            breaker=weather_breaker,
            primary_func=self._fetch_weather,
            fallback_func=self._fallback_weather,
            city=city,
            dates=dates,
        )

        # Cache discipline: Do not cache degraded fallback results for 6h
        if not results.degraded:
            await redis.setex(cache_key, 21600, json.dumps(results.model_dump()))
        else:
            await redis.setex(cache_key, 60, json.dumps(results.model_dump()))

        return results

    async def _fetch_weather(
        self, city: str, dates: str | None = None
    ) -> ProviderResult:
        """Try OpenWeather MCP."""
        errors: list[str] = []
        try:
            text = await weather_mcp_breaker.call(
                self._fetch_openweather_mcp, city=city
            )
            if text and text.strip():
                return ProviderResult(
                    text=text, source="openweather_mcp", degraded=False
                )
            raise RuntimeError("OpenWeather MCP returned empty output")
        except (TimeoutError, OSError, RuntimeError, ValueError) as exc:
            errors.append(f"MCP: {exc}")
            logger.warning("OpenWeather MCP failed: %s", exc)
        raise RuntimeError("Weather providers exhausted: " + " | ".join(errors))

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
    def _build_weather_tool_args(tool: Any, city: str) -> dict[str, Any]:
        """Adapt city/location arguments to discovered MCP tool schema."""
        fields = WeatherProvider._tool_fields(tool)
        if not fields:
            return {"city": city}
        args: dict[str, Any] = {}
        city_fields = (
            "city",
            "location",
            "place",
            "q",
            "query",
            "city_name",
            "destination",
        )
        for field in city_fields:
            if field in fields:
                args[field] = city
                break
        for field, value in (
            ("units", "metric"),
            ("unit", "metric"),
            ("lang", "en"),
            ("language", "en"),
        ):
            if field in fields and field not in args:
                args[field] = value
        return args

    @staticmethod
    def _normalize_mcp_output(output: Any) -> str:
        """Convert MCP result types into plain text."""
        if output is None:
            return ""
        if isinstance(output, str):
            return output.strip()
        if isinstance(output, (int, float, bool)):
            return str(output)
        if isinstance(output, dict):
            for key in ("text", "content", "result", "data", "output"):
                if key in output:
                    normalized = WeatherProvider._normalize_mcp_output(output[key])
                    if normalized:
                        return normalized
            return json.dumps(output, ensure_ascii=False, default=str)
        if isinstance(output, list):
            parts = [WeatherProvider._normalize_mcp_output(item) for item in output]
            return "\n".join(part for part in parts if part)
        if hasattr(output, "content"):
            return WeatherProvider._normalize_mcp_output(output.content)
        if hasattr(output, "text"):
            return WeatherProvider._normalize_mcp_output(output.text)
        return str(output)

    async def _fetch_openweather_mcp(self, city: str) -> str:
        """Discover and invoke a weather-capable OpenWeather MCP tool."""
        if not OPENWEATHER_API_KEY:
            raise ValueError("OpenWeather API key required for MCP")

        async with asyncio.timeout(10.0):
            client = await self.get_mcp_client()
            tools = await client.get_tools()
            if not tools:
                raise RuntimeError("No tools discovered from OpenWeather MCP")

            matching = [
                tool
                for tool in tools
                if getattr(tool, "name", "").lower() in APPROVED_WEATHER_TOOLS
            ]
            if not matching:
                matching = [
                    tool
                    for tool in tools
                    if any(
                        kw in getattr(tool, "name", "").lower()
                        for kw in ("weather", "forecast", "current")
                    )
                ]
            if not matching:
                raise RuntimeError(
                    "No approved weather tool found in allowlist. Discovered: "
                    + ", ".join(getattr(t, "name", "?") for t in tools)
                )

            tool = matching[0]
            args = self._build_weather_tool_args(tool, city)
            output = await tool.ainvoke(args)
            normalized = self._normalize_mcp_output(output)
            if not normalized:
                raise RuntimeError(
                    f"MCP tool '{getattr(tool, 'name', '')}' returned empty data"
                )
            return normalized

    async def _fallback_weather(
        self, city: str, dates: str | None = None
    ) -> ProviderResult:
        """Fallback when live weather services are unavailable."""
        text = (
            f"Weather Forecast for '{city}':\n"
            f"- Status: Live weather data unavailable (degraded fallback).\n"
            f"- Note: Real-time weather forecast could not be retrieved from upstream providers."
        )
        return ProviderResult(text=text, source="fallback", degraded=True)
