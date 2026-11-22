"""
Centralized Teardown Registry for managing service resources (Redis, DB, HTTP, MCP, OTel).
"""

import asyncio
import logging
from collections.abc import Awaitable, Callable

logger = logging.getLogger("travelbrain.lifecycle.teardown")

TeardownCallback = Callable[[], Awaitable[None]] | Callable[[], None]


class ServiceTeardownRegistry:
    """
    Registry for managing graceful shutdown teardown callbacks.
    """

    def __init__(self) -> None:
        self._callbacks: list[tuple[str, TeardownCallback]] = []

    def register(self, name: str, callback: TeardownCallback) -> None:
        self._callbacks.append((name, callback))
        logger.debug(f"Registered teardown callback: {name}")

    async def teardown_all(self, deadline_seconds: float = 10.0) -> None:
        logger.info(
            f"Initiating centralized service teardown (deadline: {deadline_seconds}s)..."
        )

        async def _run_teardowns():
            for name, cb in reversed(self._callbacks):
                try:
                    logger.info(f"Closing resource: {name}...")
                    if asyncio.iscoroutinefunction(cb):
                        await cb()
                    else:
                        cb()
                    logger.info(f"Successfully closed: {name}")
                except Exception:
                    logger.exception(f"Error tearing down resource '{name}'")

        try:
            await asyncio.wait_for(_run_teardowns(), timeout=deadline_seconds)
            logger.info("Centralized service teardown completed successfully.")
        except TimeoutError:
            logger.warning(
                f"Teardown deadline exceeded ({deadline_seconds}s). Forcing shutdown."
            )

        self._callbacks.clear()


_global_teardown_registry = ServiceTeardownRegistry()


def get_teardown_registry() -> ServiceTeardownRegistry:
    return _global_teardown_registry
