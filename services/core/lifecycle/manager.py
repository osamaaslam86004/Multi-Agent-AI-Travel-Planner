"""
FastAPI Lifespan Manager and Worker Lifecycle Orchestrator.
"""
import asyncio
import logging
import signal
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI

from services.core.config import get_settings
from services.core.lifecycle.teardown import get_teardown_registry

logger = logging.getLogger("travelbrain.lifecycle.manager")
@asynccontextmanager
async def lifespan_manager(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Standardized FastAPI application lifespan manager.
    Initializes configuration, telemetry, and handles graceful teardown on shutdown.
    """
    settings = get_settings()
    logger.info(
        f"Starting service '{settings.app.app_name}' (v{settings.app.app_version}) in profile: {settings.app.environment}"
    )
    try:
        yield
    finally:
        logger.info("Shutting down service and executing teardown callbacks...")
        registry = get_teardown_registry()
        await registry.teardown_all(
            deadline_seconds=settings.app.request_timeout_seconds
        )
class WorkerLifespan:
    """
    Standardized startup/shutdown orchestrator for background queue/stream workers.
    Ensures zero resource initialization at import time and safe SIGINT/SIGTERM handling.
    """
    def __init__(self, service_name: str, deadline_seconds: float = 10.0) -> None:
        self.service_name = service_name
        self.deadline_seconds = deadline_seconds
        self.running = False
        self._shutdown_event = asyncio.Event()
    def setup_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._handle_signal, sig)
            except NotImplementedError:
                # Signal handlers not implemented on some non-Unix loops
                pass
    def _handle_signal(self, sig: signal.Signals) -> None:
        logger.info(
            f"Worker '{self.service_name}' received signal {sig.name}. Initiating graceful shutdown..."
        )
        self.running = False
        self._shutdown_event.set()
    async def run(
        self,
        startup_cb: Callable[[], None] | None = None,
        work_loop_cb: Callable[[], None] | None = None,
        shutdown_cb: Callable[[], None] | None = None,
    ) -> None:
        self.running = True
        self.setup_signal_handlers()
        logger.info(f"Worker '{self.service_name}' starting up...")
        if startup_cb:
            if asyncio.iscoroutinefunction(startup_cb):
                await startup_cb()
            else:
                startup_cb()
        try:
            if work_loop_cb:
                await work_loop_cb()
            else:
                await self._shutdown_event.wait()
        except asyncio.CancelledError:
            logger.info(f"Worker '{self.service_name}' task cancelled.")
        finally:
            self.running = False
            logger.info(f"Worker '{self.service_name}' executing shutdown teardown...")
            if shutdown_cb:
                if asyncio.iscoroutinefunction(shutdown_cb):
                    await shutdown_cb()
                else:
                    shutdown_cb()
            registry = get_teardown_registry()
            await registry.teardown_all(deadline_seconds=self.deadline_seconds)
            logger.info(f"Worker '{self.service_name}' stopped cleanly.")