"""
Resilience utilities: Circuit Breakers, Exponential Backoff Retries, and Fallback Handlers.
"""

import asyncio
import logging
import random
import time
from collections.abc import Callable, Coroutine
from enum import Enum
from typing import Any

logger = logging.getLogger("travelbrain.resilience")


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreakerOpenException(Exception):
    """Raised when an operation is attempted on an open circuit breaker."""


class CircuitBreaker:
    """Production-grade asynchronous Circuit Breaker with Half-Open testing."""

    def __init__(
        self,
        name: str,
        fail_max: int = 5,
        reset_timeout: float = 30.0,
        half_open_max_trials: int = 2,
    ):
        self.name = name
        self.fail_max = fail_max
        self.reset_timeout = reset_timeout
        self.half_open_max_trials = half_open_max_trials

        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_state_change = time.time()
        self._lock = asyncio.Lock()

    async def _transition(self, new_state: CircuitState) -> None:
        if self.state != new_state:
            logger.warning(
                f"CircuitBreaker '{self.name}' transitioning from {self.state} to {new_state}"
            )
            self.state = new_state
            self.last_state_change = time.time()
            if new_state == CircuitState.CLOSED:
                self.failure_count = 0
                self.success_count = 0
            elif new_state == CircuitState.HALF_OPEN:
                self.success_count = 0

    async def call(
        self,
        func: Callable[..., Coroutine[Any, Any, Any]],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        async with self._lock:
            now = time.time()
            if self.state == CircuitState.OPEN:
                if now - self.last_state_change > self.reset_timeout:
                    await self._transition(CircuitState.HALF_OPEN)
                else:
                    raise CircuitBreakerOpenException(
                        f"CircuitBreaker '{self.name}' is OPEN. Fast-failing."
                    )

        try:
            result = await func(*args, **kwargs)
            async with self._lock:
                if self.state == CircuitState.HALF_OPEN:
                    self.success_count += 1
                    if self.success_count >= self.half_open_max_trials:
                        await self._transition(CircuitState.CLOSED)
                elif self.state == CircuitState.CLOSED:
                    self.failure_count = 0
            return result
        except Exception as exc:
            async with self._lock:
                self.failure_count += 1
                if (
                    self.state == CircuitState.HALF_OPEN
                    or self.failure_count >= self.fail_max
                ):
                    await self._transition(CircuitState.OPEN)
            raise exc


async def retry_with_backoff(
    func: Callable[..., Coroutine[Any, Any, Any]],
    *args: Any,
    max_retries: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 10.0,
    backoff_factor: float = 2.0,
    jitter: bool = True,
    **kwargs: Any,
) -> Any:
    """Execute coroutine with exponential backoff and randomized jitter."""
    delay = initial_delay
    last_exception = None

    for attempt in range(1, max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except Exception as exc:
            last_exception = exc
            if attempt == max_retries:
                logger.error(
                    f"Retry exhausted ({attempt}/{max_retries}) for {func.__name__}: {exc}"
                )
                raise exc

            sleep_duration = min(delay, max_delay)
            if jitter:
                sleep_duration = sleep_duration * (0.5 + random.random())
            logger.warning(
                f"Attempt {attempt}/{max_retries} failed for {func.__name__}: {exc}. "
                f"Retrying in {sleep_duration:.2f}s..."
            )
            await asyncio.sleep(sleep_duration)
            delay *= backoff_factor

    raise last_exception or RuntimeError("Unexpected retry termination")


async def resilient_execute(
    breaker: CircuitBreaker,
    primary_func: Callable[..., Coroutine[Any, Any, Any]],
    fallback_func: Callable[..., Coroutine[Any, Any, Any]] | None = None,
    *args: Any,
    **kwargs: Any,
) -> Any:
    """
    Executes primary function guarded by Circuit Breaker and Retries.
    If unavailable or failed, executes fallback function gracefully.
    """
    try:
        return await breaker.call(
            lambda: retry_with_backoff(primary_func, *args, **kwargs)
        )
    except Exception as exc:
        logger.error(
            f"Execution failed under breaker '{breaker.name}': {exc}. Invoking fallback..."
        )
        if fallback_func:
            return await fallback_func(*args, **kwargs)
        raise exc
