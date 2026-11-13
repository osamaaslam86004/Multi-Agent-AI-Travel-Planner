"""Centralized tool registry and tool adapters decoupling tool execution from agent nodes."""

import asyncio
import inspect
from collections.abc import Callable
from typing import (
    Any,
    Protocol,
    runtime_checkable,
)


@runtime_checkable
class ToolAdapter(Protocol):
    """Protocol for decoupling tool execution mechanics from agent logic."""

    name: str

    def execute(self, **kwargs: Any) -> Any:
        """Execute tool synchronously."""
        ...

    async def aexecute(self, **kwargs: Any) -> Any:
        """Execute tool asynchronously."""
        ...


class BaseToolAdapter(ToolAdapter):
    """Wrapper adapting functions into standard ToolAdapter objects."""

    def __init__(
        self, name: str, func: Callable[..., Any], description: str = ""
    ) -> None:
        self.name = name
        self.func = func
        self.description = description
        self.is_async = inspect.iscoroutinefunction(func)

    def execute(self, **kwargs: Any) -> Any:
        if self.is_async:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                return asyncio.run(self.func(**kwargs))
            else:
                # If running inside an existing event loop, create a task or run via nest_asyncio / run_async
                from src.utils.async_utils import run_async

                return run_async(self.func(**kwargs))
        return self.func(**kwargs)

    async def aexecute(self, **kwargs: Any) -> Any:
        if self.is_async:
            return await self.func(**kwargs)
        return self.func(**kwargs)


class ToolRegistry:
    """Centralized registry for managing and invoking tool adapters across MCP servers."""

    def __init__(self) -> None:
        self._registry: dict[str, ToolAdapter] = {}

    def register(self, adapter: ToolAdapter) -> None:
        """Register a ToolAdapter instance."""
        self._registry[adapter.name] = adapter

    def register_function(
        self, name: str, func: Callable[..., Any], description: str = ""
    ) -> ToolAdapter:
        """Helper to register a callable directly as a tool."""
        adapter = BaseToolAdapter(name=name, func=func, description=description)
        self.register(adapter)
        return adapter

    def get_tool(self, name: str) -> ToolAdapter:
        """Retrieve a registered tool adapter by name."""
        if name not in self._registry:
            available = ", ".join(sorted(self._registry.keys())) or "none"
            raise KeyError(
                f"Tool '{name}' not found in registry. Available tools: {available}"
            )
        return self._registry[name]

    def execute_tool(self, tool_name: str, **kwargs: Any) -> Any:
        """Execute a tool synchronously by name."""
        tool = self.get_tool(tool_name)
        return tool.execute(**kwargs)

    async def aexecute_tool(self, tool_name: str, **kwargs: Any) -> Any:
        """Execute a tool asynchronously by name."""
        tool = self.get_tool(tool_name)
        return await tool.aexecute(**kwargs)

    def list_tools(self) -> list[str]:
        """List names of all registered tools."""
        return sorted(list(self._registry.keys()))


# Global default ToolRegistry instance
default_tool_registry = ToolRegistry()


def _initialize_default_registry(registry: ToolRegistry) -> None:
    """Populate default MCP tools into the registry."""
    from src.mcp_servers.local import (
        aviation_mcp_call,
        forecast_mcp_search,
        weather_mcp_search,
    )
    from src.mcp_servers.remote import tavily_mcp_search

    registry.register_function(
        "aviation_mcp_call", aviation_mcp_call, "Call AviationStack MCP tool"
    )
    registry.register_function(
        "weather_mcp_search", weather_mcp_search, "Get current weather conditions"
    )
    registry.register_function(
        "forecast_mcp_search", forecast_mcp_search, "Get weather forecast"
    )
    registry.register_function(
        "tavily_mcp_search", tavily_mcp_search, "Search hotels / web via Tavily"
    )


_initialize_default_registry(default_tool_registry)
