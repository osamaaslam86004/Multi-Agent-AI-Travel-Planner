"""Unified logging, performance monitoring, and telemetry tracing hooks."""

import functools
import inspect
import logging
import time
from collections.abc import Callable
from typing import Any, TypeVar, cast

# Setup structured logger for telemetry
logger = logging.getLogger("travelbrain.telemetry")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class TelemetryCollector:
    """In-memory telemetry collector recording performance metrics and execution traces."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def record(
        self,
        operation_name: str,
        duration_sec: float,
        success: bool,
        error: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        record_data = {
            "timestamp": time.time(),
            "operation": operation_name,
            "duration_ms": round(duration_sec * 1000, 2),
            "success": success,
            "error": error,
            "metadata": metadata or {},
        }
        self.records.append(record_data)

    def get_records(self) -> list[dict[str, Any]]:
        return list(self.records)

    def clear(self) -> None:
        self.records.clear()


# Global telemetry collector instance
global_telemetry = TelemetryCollector()

F = TypeVar("F", bound=Callable[..., Any])


def track_performance(name: str | None = None) -> Callable[[F], F]:
    """
    Decorator for tracking performance, logging duration, and collecting telemetry traces
    for both sync and async agent operations and tool calls.
    """

    def decorator(func: F) -> F:
        op_name = name or func.__name__

        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                start_time = time.perf_counter()
                logger.info(f"Starting async operation: {op_name}")
                try:
                    result = await func(*args, **kwargs)
                    duration = time.perf_counter() - start_time
                    logger.info(
                        f"Completed async operation: {op_name} in {duration * 1000:.2f}ms"
                    )
                    global_telemetry.record(op_name, duration, success=True)
                    return result
                except Exception as e:
                    duration = time.perf_counter() - start_time
                    logger.error(
                        f"Failed async operation: {op_name} after {duration * 1000:.2f}ms with error: {e}"
                    )
                    global_telemetry.record(
                        op_name, duration, success=False, error=str(e)
                    )
                    raise

            return cast(F, async_wrapper)

        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                start_time = time.perf_counter()
                logger.info(f"Starting operation: {op_name}")
                try:
                    result = func(*args, **kwargs)
                    duration = time.perf_counter() - start_time
                    logger.info(
                        f"Completed operation: {op_name} in {duration * 1000:.2f}ms"
                    )
                    global_telemetry.record(op_name, duration, success=True)
                    return result
                except Exception as e:
                    duration = time.perf_counter() - start_time
                    logger.error(
                        f"Failed operation: {op_name} after {duration * 1000:.2f}ms with error: {e}"
                    )
                    global_telemetry.record(
                        op_name, duration, success=False, error=str(e)
                    )
                    raise

            return cast(F, sync_wrapper)

    return decorator
