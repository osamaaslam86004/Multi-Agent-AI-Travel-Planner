"""
MCP Integrations Domain Settings.
"""
from pydantic import Field

from services.core.config.base import BaseDomainSettings


class MCPSettings(BaseDomainSettings):
    flight_mcp_command: str | None = None
    aviationstack_api_key: str | None = None
    hotel_mcp_command: str | None = Field(
        default="npx -y @modelcontextprotocol/server-duckduckgo"
    )
    weather_mcp_command: str | None = Field(default="openweather-mcp")
    mcp_timeout_seconds: float = 15.0
    @classmethod
    def load(cls) -> "MCPSettings":
        aliases = {
            "flight_mcp_command": "AVIATIONSTACK_MCP_COMMAND",
            "aviationstack_api_key": "AVIATIONSTACK_API_KEY",
            "hotel_mcp_command": "DUCKDUCKGO_MCP_COMMAND",
            "weather_mcp_command": "OPENWEATHER_MCP_COMMAND",
        }
        return cls.load_from_env(prefix="MCP", aliases=aliases)