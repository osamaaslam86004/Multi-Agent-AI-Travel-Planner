"""Turns the user query into concrete flight guidance using AviationStack MCP via ToolRegistry."""

from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from src.agents.base import BaseAgent
from src.agents.prompts_registry import default_prompt_registry
from src.clients.llm_provider import get_llm_provider
from src.config.settings import settings
from src.graph.state import TravelState
from src.mcp_servers.registry import default_tool_registry
from src.utils.async_utils import bump_llm_calls, truncate
from src.utils.telemetry import track_performance


class FlightAgent(BaseAgent):
    """Enterprise Flight Planner agent implementing AgentProtocol."""

    def __init__(self) -> None:
        super().__init__(name="flight_agent")
        self.llm_provider = get_llm_provider("groq")
        self.prompt_registry = default_prompt_registry
        self.tool_registry = default_tool_registry

    @track_performance("flight_agent")
    def execute(self, state: TravelState) -> dict[str, Any]:
        query = state["user_query"]
        try:
            airports = self.tool_registry.execute_tool(
                "aviation_mcp_call", tool_name="list_airports"
            )
            airlines = self.tool_registry.execute_tool(
                "aviation_mcp_call", tool_name="list_airlines"
            )

            prompt_content = self.prompt_registry.format_prompt(
                "flight_user",
                query=query,
                airport_data=truncate(
                    airports, settings.truncation.airport_data_char_limit
                ),
                airline_data=truncate(
                    airlines, settings.truncation.airline_data_char_limit
                ),
            )
            system_prompt = self.prompt_registry.get_prompt("flight_system")

            response = self.llm_provider.invoke(
                [
                    SystemMessage(content=system_prompt),
                    HumanMessage(content=prompt_content),
                ]
            )
            flight_data = response.content
        except Exception as e:
            flight_data = f"Flight information unavailable: {e!s}"

        return {
            "flight_results": flight_data,
            "messages": [AIMessage(content="Flight recommendations generated")],
            "llm_calls": bump_llm_calls(state),
        }


# Singleton agent instance and node callable
_flight_agent_instance = FlightAgent()


def flight_agent(state: TravelState) -> dict[str, Any]:
    """LangGraph node callable for flight agent."""
    return _flight_agent_instance(state)
