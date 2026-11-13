"""Finds hotel options for the destination through Tavily MCP server via ToolRegistry."""

from typing import Any

from langchain_core.messages import AIMessage

from src.agents.base import BaseAgent
from src.agents.prompts_registry import default_prompt_registry
from src.graph.state import TravelState
from src.mcp_servers.registry import default_tool_registry
from src.utils.async_utils import bump_llm_calls
from src.utils.telemetry import track_performance


class HotelAgent(BaseAgent):
    """Enterprise Hotel Planner agent implementing AgentProtocol."""

    def __init__(self) -> None:
        super().__init__(name="hotel_agent")
        self.prompt_registry = default_prompt_registry
        self.tool_registry = default_tool_registry

    @track_performance("hotel_agent")
    def execute(self, state: TravelState) -> dict[str, Any]:
        query = self.prompt_registry.format_prompt(
            "hotel_search_query", user_query=state["user_query"]
        )
        hotel_results = self.tool_registry.execute_tool(
            "tavily_mcp_search", query=query
        )
        return {
            "hotel_results": hotel_results,
            "messages": [AIMessage(content="Hotel information fetched.")],
            "llm_calls": bump_llm_calls(state),
        }


# Singleton agent instance and node callable
_hotel_agent_instance = HotelAgent()


def hotel_agent(state: TravelState) -> dict[str, Any]:
    """LangGraph node callable for hotel agent."""
    return _hotel_agent_instance(state)
