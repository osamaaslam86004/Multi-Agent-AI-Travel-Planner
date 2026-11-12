# src/mcp_servers/local.py
"""
Local MCP servers, spawned as stdio child processes.
"""

from src.clients.cache import async_cached
from src.config.settings import settings
from src.mcp_servers.config import (
    WEATHER_SERVER_PATH,
    load_tools,
    require_tools,
)

AVIATION_SERVER_NAME = "aviationstack"
WEATHER_SERVER_NAME = "weather"
CURRENT_WEATHER_TOOL = "get_current_weather"
FORECAST_TOOL = "get_forecast"

# Reference data that effectively never changes, using TTLs from settings.redis
LONG_LIVED_AVIATION_TOOLS = {
    "list_airports": settings.redis.ttl_airports,
    "list_airlines": settings.redis.ttl_airlines,
}

# =========================
# AviationStack
# =========================
_aviation_tools: dict = {}


async def _get_aviation_tools() -> dict:
    global _aviation_tools

    if _aviation_tools:
        return _aviation_tools

    tools = await load_tools(AVIATION_SERVER_NAME)

    if not tools:
        raise RuntimeError("AviationStack MCP connected but returned no tools.")

    _aviation_tools = tools
    return _aviation_tools


async def _aviation_call(tool_name: str, tool_args: dict | None = None):
    tools = await _get_aviation_tools()
    tool = tools.get(tool_name)

    if tool is None:
        available = ", ".join(sorted(tools)) or "none"
        raise ValueError(
            f"AviationStack tool '{tool_name}' was not found. "
            f"Available tools: {available}"
        )
    return await tool.ainvoke(tool_args or {})


@async_cached(prefix="aviation:reference", ttl=settings.redis.ttl_airports)
async def _aviation_call_cached(tool_name: str, tool_args: dict | None = None):
    return await _aviation_call(tool_name, tool_args)


async def aviation_mcp_call(tool_name: str, tool_args: dict | None = None):
    """Call an AviationStack tool."""

    if tool_name in LONG_LIVED_AVIATION_TOOLS:
        return await _aviation_call_cached(tool_name, tool_args)
    return await _aviation_call(tool_name, tool_args)


# =========================
# Weather
# =========================
_weather_tools: dict = {}


async def _get_weather_tools() -> dict:
    global _weather_tools

    if _weather_tools:
        return _weather_tools

    if not WEATHER_SERVER_PATH.exists():
        raise FileNotFoundError(
            f"Weather MCP server file was not found: {WEATHER_SERVER_PATH}"
        )

    tools = await load_tools(WEATHER_SERVER_NAME)
    require_tools(
        WEATHER_SERVER_NAME,
        tools,
        CURRENT_WEATHER_TOOL,
        FORECAST_TOOL,
    )
    _weather_tools = tools
    return _weather_tools


@async_cached(prefix="weather:current", ttl=settings.redis.ttl_weather)
async def weather_mcp_search(city: str):
    """Current conditions with TTL from settings.redis."""

    tools = await _get_weather_tools()
    return await tools[CURRENT_WEATHER_TOOL].ainvoke({"city": city})


@async_cached(prefix="weather:forecast", ttl=settings.redis.ttl_forecast)
async def forecast_mcp_search(city: str):
    """Multi-day forecast with TTL from settings.redis."""

    tools = await _get_weather_tools()
    return await tools[FORECAST_TOOL].ainvoke({"city": city})
