"""Wires the agents together into the LangGraph workflow with dynamic routing support."""

from collections.abc import Callable
from functools import lru_cache
from typing import Any

from langgraph.graph import END, START, StateGraph

from src.agents.base import AgentProtocol
from src.agents.final_agent import final_agent
from src.agents.flight_agent import flight_agent
from src.agents.hotel_agent import hotel_agent
from src.agents.itinerary_agent import itinerary_agent
from src.agents.weather_agent import weather_agent
from src.clients.checkpointer import get_checkpointer
from src.config.session import require, resolve_database_url
from src.graph.state import TravelState

DEFAULT_PIPELINE = [
    "flight_agent",
    "hotel_agent",
    "weather_agent",
    "itinerary_agent",
    "final_agent",
]

AGENT_NODE_REGISTRY: dict[
    str, Callable[[TravelState], dict[str, Any]] | AgentProtocol
] = {
    "flight_agent": flight_agent,
    "hotel_agent": hotel_agent,
    "weather_agent": weather_agent,
    "itinerary_agent": itinerary_agent,
    "final_agent": final_agent,
}


def build_dynamic_graph(
    pipeline_config: list[str | dict[str, Any]] | None = None,
    custom_nodes: dict[str, Callable[..., Any] | AgentProtocol] | None = None,
) -> StateGraph:
    """
    Constructs LangGraph pipelines dynamically from ordered configuration lists
    rather than hardcoded sequential edges.

    Args:
        pipeline_config: Ordered list of node names or configuration dictionaries.
        custom_nodes: Optional dictionary of additional node names and node callables/agents.

    Returns:
        Uncompiled StateGraph instance built according to the dynamic configuration.
    """
    nodes_map = dict(AGENT_NODE_REGISTRY)
    if custom_nodes:
        nodes_map.update(custom_nodes)

    if not pipeline_config:
        pipeline_sequence = DEFAULT_PIPELINE
    else:
        pipeline_sequence = []
        for item in pipeline_config:
            if isinstance(item, str):
                pipeline_sequence.append(item)
            elif isinstance(item, dict) and "name" in item:
                pipeline_sequence.append(item["name"])

    if not pipeline_sequence:
        raise ValueError("Pipeline sequence configuration cannot be empty.")

    graph = StateGraph(TravelState)

    # Register nodes into graph
    for node_name in pipeline_sequence:
        if node_name not in nodes_map:
            available = ", ".join(sorted(nodes_map.keys()))
            raise KeyError(
                f"Node '{node_name}' not found in registry. Available nodes: {available}"
            )
        graph.add_node(node_name, nodes_map[node_name])

    # Dynamic sequential routing
    graph.add_edge(START, pipeline_sequence[0])
    for i in range(len(pipeline_sequence) - 1):
        graph.add_edge(pipeline_sequence[i], pipeline_sequence[i + 1])
    graph.add_edge(pipeline_sequence[-1], END)

    return graph


def build_graph() -> StateGraph:
    """Build the default uncompiled graph. Useful for tests and visualization."""
    return build_dynamic_graph(DEFAULT_PIPELINE)


@lru_cache(maxsize=4)
def _compiled_graph(database_url: str):
    return build_graph().compile(checkpointer=get_checkpointer(database_url))


def get_travel_graph():
    """
    Compile the graph against whichever database the current session
    resolves to. One compiled graph is cached per distinct URL.
    """
    require("DATABASE_URL")
    return _compiled_graph(resolve_database_url())
