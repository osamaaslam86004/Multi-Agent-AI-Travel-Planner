# src/mcp_servers/config.py
"""
MCP server registry, split by where the server actually runs.
REMOTE servers are reached over HTTP and are operated by someone else.
LOCAL servers are spawned as child processes over stdio on this machine.
"""

import os
import sys
from functools import lru_cache
from pathlib import Path

from langchain_mcp_adapters.client import MultiServerMCPClient

from src.config.settings import settings

# This package holds the weather server we ship ourselves.
MCP_DIR = Path(__file__).resolve().parent
WEATHER_SERVER_PATH = MCP_DIR / "weather_server.py"


def _child_env(**overrides: str) -> dict:
    """
    Full copy of the current environment plus explicit overrides.
    """
    env = os.environ.copy()
    env.update({key: value or "" for key, value in overrides.items()})
    return env


# =========================
# Remote MCP servers (HTTP)
# =========================
REMOTE_SERVERS = {
    "tavily": {
        "transport": "streamable_http",
        "url": f"https://mcp.tavily.com/mcp/?tavilyApiKey={settings.apis.tavily_api_key.get_secret_value()}",
    },
}
# =========================
# Local MCP servers (stdio)
# =========================
LOCAL_SERVERS = {
    "aviationstack": {
        "transport": "stdio",
        "command": sys.executable,
        "args": ["-m", "aviationstack_mcp"],
        "env": _child_env(
            AVIATION_STACK_API_KEY=settings.apis.aviationstack_api_key.get_secret_value(),
        ),
    },
    "weather": {
        "transport": "stdio",
        "command": sys.executable,
        "args": [str(WEATHER_SERVER_PATH)],
        "env": _child_env(
            OPENWEATHER_API_KEY=settings.apis.openweather_api_key.get_secret_value(),
        ),
    },
}
MCP_SERVERS = {**REMOTE_SERVERS, **LOCAL_SERVERS}


@lru_cache(maxsize=1)
def get_client() -> MultiServerMCPClient:
    """Shared client covering every configured server."""
    return MultiServerMCPClient(MCP_SERVERS)


async def load_tools(server_name: str) -> dict:
    """Load one server's tools as {name: tool}."""
    tools = await get_client().get_tools(server_name=server_name)
    return {tool.name: tool for tool in tools}


def require_tools(server_name: str, tools: dict, *names: str) -> None:
    """Raise a readable error when a server is missing expected tools."""
    missing = [name for name in names if name not in tools]
    if not missing:
        return
    available = ", ".join(sorted(tools)) or "none"
    raise RuntimeError(
        f"Missing {server_name} MCP tools: {', '.join(missing)}. "
        f"Available tools: {available}"
    )
