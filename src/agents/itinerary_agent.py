"""Combines flight, hotel and weather results into a day-by-day itinerary."""

from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from src.agents.base import BaseAgent
from src.agents.prompts_registry import default_prompt_registry
from src.clients.llm_provider import get_llm_provider
from src.graph.state import TravelState
from src.utils.async_utils import bump_llm_calls
from src.utils.telemetry import track_performance


class ItineraryAgent(BaseAgent):
    """Enterprise Itinerary Planner agent implementing AgentProtocol."""

    def __init__(self) -> None:
        super().__init__(name="itinerary_agent")
        self.llm_provider = get_llm_provider("groq")
        self.prompt_registry = default_prompt_registry

    @track_performance("itinerary_agent")
    def execute(self, state: TravelState) -> dict[str, Any]:
        prompt = self.prompt_registry.format_prompt(
            "itinerary_user",
            user_query=state["user_query"],
            flight_results=state["flight_results"],
            hotel_results=state["hotel_results"],
            weather_results=state["weather_results"],
        )
        system_prompt = self.prompt_registry.get_prompt("itinerary_system")
        response = self.llm_provider.invoke(
            [
                SystemMessage(content=system_prompt),
                HumanMessage(content=prompt),
            ]
        )
        return {
            "itinerary": response.content,
            "messages": [response],
            "llm_calls": bump_llm_calls(state),
        }


# Singleton agent instance and node callable
_itinerary_agent_instance = ItineraryAgent()


def itinerary_agent(state: TravelState) -> dict[str, Any]:
    """LangGraph node callable for itinerary agent."""
    return _itinerary_agent_instance(state)
