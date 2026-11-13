"""Graph module package exposing TravelState, dynamic graph builder, and runner."""

from src.graph.state import TravelState, initial_state


def build_dynamic_graph(*args, **kwargs):
    """Dynamic graph builder factory."""
    from src.graph.graph import build_dynamic_graph as _bdg

    return _bdg(*args, **kwargs)


def build_graph(*args, **kwargs):
    """Default graph builder factory."""
    from src.graph.graph import build_graph as _bg

    return _bg(*args, **kwargs)


def get_travel_graph(*args, **kwargs):
    """Compiled session graph resolver."""
    from src.graph.graph import get_travel_graph as _gtg

    return _gtg(*args, **kwargs)


def run_travel_agent(*args, **kwargs):
    """Graph runner execution helper."""
    from src.graph.runner import run_travel_agent as _rta

    return _rta(*args, **kwargs)


__all__ = [
    "TravelState",
    "build_dynamic_graph",
    "build_graph",
    "get_travel_graph",
    "initial_state",
    "run_travel_agent",
]
