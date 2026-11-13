"""Base interfaces, abstract protocols, and foundation classes for TravelBrain agents."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from src.graph.state import TravelState
else:
    TravelState = dict[str, Any]


@runtime_checkable
class AgentProtocol(Protocol):
    """Runtime-checkable protocol defining the execution contract for all agent nodes."""

    def __call__(self, state: TravelState) -> dict[str, Any]:
        """Execute the agent given the current workflow state."""
        ...

    def execute(self, state: TravelState) -> dict[str, Any]:
        """Execute the agent given the current workflow state (explicit method)."""
        ...


class BaseAgent(ABC, AgentProtocol):
    """Abstract base class for all enterprise TravelBrain agents."""

    def __init__(self, name: str | None = None) -> None:
        self.name = name or self.__class__.__name__

    @abstractmethod
    def execute(self, state: TravelState) -> dict[str, Any]:
        """Core execution logic to be implemented by concrete agents."""

    def __call__(self, state: TravelState) -> dict[str, Any]:
        """Enables the agent instance to be invoked directly as a LangGraph node callable."""
        return self.execute(state)
