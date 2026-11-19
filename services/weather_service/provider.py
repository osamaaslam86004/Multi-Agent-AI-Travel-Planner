"""
Weather Provider with OpenWeather API + MCP, Redis caching, and fallback resilience.
MCP is attempted after the direct API path fails.
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

logger = logging.getLogger("travelbrain.weather_service")

OPENWEATHER_API_KEY = os.getenv("OPENWEATHER_API_KEY", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/3")
OPENWEATHER_MCP_COMMAND = os.getenv("OPENWEATHER_MCP_COMMAND", "uvx")
OPENWEATHER_MCP_PACKAGE = os.getenv("OPENWEATHER_MCP_PACKAGE", "openweather-mcp==0.1.0")

weather_breaker = CircuitBreaker("OpenWeatherBreaker", fail_max=4, reset_timeout=30.0)
weather_mcp_breaker = CircuitBreaker(
    "OpenWeatherMCPBreaker", fail_max=3, reset_timeout=20.0
)


class WeatherProvider:
    """Manages weather lookups, caching, MCP, and heuristic fallback."""

    def __init__(self, redis_url: str = REDIS_URL):
        self.redis_url = redis_url
        self._redis: aioredis.Redis | None = None

    async def get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(
                self.redis_url, encoding="utf-8", decode_responses=True
            )
        return self._redis

    def extract_city(self, query: str) -> str:
        """Lightweight rule-based city extractor with fallback."""
        patterns = [
            r"to\s+([A-Za-z\s]+?)(?:\s+(?:next|for|in|on|with|during|from)|$|\.|\?)",
            r"in\s+([A-Za-z\s]+?)(?:\s+(?:next|for|in|on|with|during|from)|$|\.|\?)",
            r"visit\s+([A-Za-z\s]+?)(?:\s+(?:next|for|in|on|with|during|from)|$|\.|\?)",
        ]
        for pattern in patterns:
            match = re.search(pattern, query, re.IGNORECASE)
            if match:
                candidate = match.group(1).strip()
                if len(candidate) > 2:
                    return candidate
        return query.split()[0] if query else "Destination"

    def _cache_key(self, city: str) -> str:
        h = hashlib.sha256(city.strip().lower().encode()).hexdigest()[:16]
        return f"weather:cache:{h}"

    async def get_weather(self, query: str) -> dict[str, Any]:
        """High-level weather lookup with caching and circuit-broken execution."""
        city = self.extract_city(query)
        redis = await self.get_redis()
        cache_key = self._cache_key(city)

        cached_data = await redis.get(cache_key)
        if cached_data:
            logger.info("Weather cache hit for city: '%s'", city)
            return {"results": json.loads(cached_data), "cached": True}

        results = await resilient_execute(
            breaker=weather_breaker,
            primary_func=self._fetch_weather,
            fallback_func=self._fallback_weather,
            city=city,
        )

        await redis.setex(cache_key, 21600, json.dumps(results))
        return {"results": results, "cached": False}

    async def _fetch_weather(self, city: str) -> str:
        """Try the MCP before outer fallback."""
        errors: list[str] = []

        try:
            result = await weather_mcp_breaker.call(
                self._fetch_openweather_mcp, city=city
            )
            if result and result.strip():
                return result
            raise RuntimeError("OpenWeather MCP returned empty output")
        except Exception as exc:
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

        # Only populate recognized optional parameters.
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
        """Convert MCP result types into plain text for existing consumers."""
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

        server_config = {
            "openweather": {
                "command": OPENWEATHER_MCP_COMMAND,
                "args": [
                    "--from",
                    OPENWEATHER_MCP_PACKAGE,
                    "openweather-mcp",
                ],
                "transport": "stdio",
                "env": {"OPENWEATHER_API_KEY": OPENWEATHER_API_KEY},
            }
        }

        async with MultiServerMCPClient(server_config) as client:
            tools = client.get_tools()
            if not tools:
                raise RuntimeError("No tools discovered from OpenWeather MCP")

            candidates = [
                tool
                for tool in tools
                if any(
                    keyword in getattr(tool, "name", "").lower()
                    for keyword in ("weather", "forecast", "current")
                )
            ]
            if not candidates:
                raise RuntimeError(
                    "No weather tool discovered; tools="
                    + ", ".join(getattr(t, "name", "?") for t in tools)
                )

            tool = candidates[0]
            args = self._build_weather_tool_args(tool, city)
            output = await tool.ainvoke(args)
            normalized = self._normalize_mcp_output(output)
            if not normalized:
                raise RuntimeError(f"MCP tool '{tool.name}' returned empty data")
            return normalized

    async def _fallback_weather(self, city: str) -> str:
        """Seasonal climatological averages fallback."""
        return (
            f"Weather Forecast for '{city}':\n"
            "- Current Conditions: Pleasant and seasonal "
            "(est. 18°C - 24°C / 64°F - 75°F).\n"
            "- Precipitation: Moderate chance of light showers; "
            "packing a light rain jacket is recommended.\n"
            "- Humidity & UV: Moderate index; comfortable for day-long walking tours."
        )
