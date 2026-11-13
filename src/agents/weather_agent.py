"""Fetches current weather and forecast for extracted destination via ToolRegistry."""

from typing import Any

from langchain_core.messages import AIMessage

from src.agents.base import BaseAgent
from src.agents.destination import extract_destination
from src.agents.prompts_registry import default_prompt_registry
from src.graph.state import TravelState
from src.mcp_servers.registry import default_tool_registry
from src.utils.telemetry import track_performance


class WeatherAgent(BaseAgent):
    """Enterprise Weather Planner agent implementing AgentProtocol."""

    def __init__(self) -> None:
        super().__init__(name="weather_agent")
        self.prompt_registry = default_prompt_registry
        self.tool_registry = default_tool_registry

    @track_performance("weather_agent")
    def execute(self, state: TravelState) -> dict[str, Any]:
        city = extract_destination(state["user_query"])
        weather_data = self.tool_registry.execute_tool("weather_mcp_search", city=city)
        forecast_data = self.tool_registry.execute_tool(
            "forecast_mcp_search", city=city
        )

        formatted_weather = self.prompt_registry.format_prompt(
            "weather_results_template",
            weather_data=weather_data,
            forecast_data=forecast_data,
        )
        return {
            "weather_results": formatted_weather,
            "messages": [AIMessage(content="Weather information fetched")],
        }


# Singleton agent instance and node callable
_weather_agent_instance = WeatherAgent()


def weather_agent(state: TravelState) -> dict[str, Any]:
    """LangGraph node callable for weather agent."""
    return _weather_agent_instance(state)
