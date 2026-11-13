"""Formats everything the other agents produced into the user-facing answer."""

from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from src.agents.base import BaseAgent
from src.agents.prompts_registry import default_prompt_registry
from src.clients.llm_provider import get_llm_provider
from src.graph.state import TravelState
from src.utils.async_utils import bump_llm_calls
from src.utils.telemetry import track_performance


class FinalAgent(BaseAgent):
    """Enterprise Final Synthesizer agent implementing AgentProtocol."""

    def __init__(self) -> None:
        super().__init__(name="final_agent")
        self.llm_provider = get_llm_provider("groq")
        self.prompt_registry = default_prompt_registry

    @track_performance("final_agent")
    def execute(self, state: TravelState) -> dict[str, Any]:
        prompt = self.prompt_registry.format_prompt(
            "final_user",
            user_query=state["user_query"],
            flight_results=state["flight_results"],
            hotel_results=state["hotel_results"],
            weather_results=state["weather_results"],
            itinerary=state["itinerary"],
        )
        system_prompt = self.prompt_registry.get_prompt("final_system")
        response = self.llm_provider.invoke(
            [
                SystemMessage(content=system_prompt),
                HumanMessage(content=prompt),
            ]
        )
        return {
            "messages": [response],
            "llm_calls": bump_llm_calls(state),
        }


# Singleton agent instance and node callable
_final_agent_instance = FinalAgent()


def final_agent(state: TravelState) -> dict[str, Any]:
    """LangGraph node callable for final agent."""
    return _final_agent_instance(state)
