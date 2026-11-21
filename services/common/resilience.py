"""
Resilience utilities: Shared Redis Circuit Breakers, Non-Transient Error Filtering,
Bounded HALF_OPEN Trial Concurrency, Retry-After Header Handling, and Exponential Backoff.
"""

import asyncio
import json
import logging
import random
import time
from collections.abc import Callable, Coroutine
from enum import Enum
from typing import Any

import httpx

from services.common.telemetry import update_breaker_metric

logger = logging.getLogger("travelbrain.resilience")


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreakerOpenException(Exception):
    """Raised when an operation is attempted on an open circuit breaker."""


def is_transient_error(exc: Exception) -> bool:
    """
    Classifies errors into transient (network/timeout/5xx) vs non-transient (config/validation/4xx).
    Non-transient errors (e.g. ValueError, KeyError, bad API key config) MUST NOT trip circuit breakers.
    """
    if isinstance(
        exc, (ValueError, KeyError, TypeError, AttributeError, json.JSONDecodeError)
    ):
        return False

    if (
        isinstance(exc, httpx.HTTPStatusError)
        and 400 <= exc.response.status_code < 500
        and exc.response.status_code != 429
    ):
        return False

    return bool(
        isinstance(
            exc,
            (
                httpx.HTTPError,
                TimeoutError,
                OSError,
                ConnectionError,
                asyncio.TimeoutError,
                RuntimeError,
            ),
        )
    )


def parse_retry_after(exc: Exception) -> float | None:
    """Extract Retry-After header value in seconds from exception if present."""
    if isinstance(exc, httpx.HTTPStatusError) and exc.response is not None:
        header_val = exc.response.headers.get("Retry-After")
        if header_val:
            try:
                return float(header_val)
            except ValueError:
                pass
    if hasattr(exc, "retry_after") and isinstance(exc.retry_after, (int, float)):
        return float(exc.retry_after)
    return None


class CircuitBreaker:
    """
    Production-grade Asynchronous Circuit Breaker with optional Redis shared state backend,
    strictly bounded HALF_OPEN trial concurrency, non-transient exception filtering, and Retry-After support.
    """

    def __init__(
        self,
        name: str,
        fail_max: int = 5,
        reset_timeout: float = 30.0,
        half_open_max_trials: int = 2,
        redis_client: Any = None,
    ):
        self.name = name
        self.fail_max = fail_max
        self.reset_timeout = reset_timeout
        self.half_open_max_trials = half_open_max_trials
        self.redis = redis_client

        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_state_change = time.time()
        self.dynamic_reset_timeout = reset_timeout
        self._lock = asyncio.Lock()
        self._half_open_trial_active = False

    async def _get_redis_state(self) -> tuple[CircuitState, int, int, float]:
        if not self.redis:
            return (
                self.state,
                self.failure_count,
                self.success_count,
                self.last_state_change,
            )
        try:
            pipe = self.redis.pipeline()
            pipe.get(f"breaker:{self.name}:state")
            pipe.get(f"breaker:{self.name}:failures")
            pipe.get(f"breaker:{self.name}:successes")
            pipe.get(f"breaker:{self.name}:last_change")
            results = await pipe.execute()

            st = results[0] or CircuitState.CLOSED.value
            fc = int(results[1] or 0)
            sc = int(results[2] or 0)
            lc = float(results[3] or time.time())
            return CircuitState(st), fc, sc, lc
        except (OSError, RuntimeError, TimeoutError, ValueError) as e:
            logger.debug(
                "Redis state fetch exception for breaker '%s': %s", self.name, e
            )
            return (
                self.state,
                self.failure_count,
                self.success_count,
                self.last_state_change,
            )

    async def _set_redis_state(
        self, state: CircuitState, failures: int, successes: int, last_change: float
    ) -> None:
        if not self.redis:
            return
        try:
            pipe = self.redis.pipeline()
            pipe.set(f"breaker:{self.name}:state", state.value)
            pipe.set(f"breaker:{self.name}:failures", failures)
            pipe.set(f"breaker:{self.name}:successes", successes)
            pipe.set(f"breaker:{self.name}:last_change", str(last_change))
            await pipe.execute()
        except (OSError, RuntimeError, TimeoutError, ValueError) as e:
            logger.debug("Redis state set exception for breaker '%s': %s", self.name, e)

    async def _transition(
        self, new_state: CircuitState, custom_reset_timeout: float | None = None
    ) -> None:
        current_st, _, _, _ = await self._get_redis_state()
        if current_st != new_state:
            logger.warning(
                f"CircuitBreaker '{self.name}' transitioning from {current_st} to {new_state}"
            )
            now = time.time()
            self.state = new_state
            self.last_state_change = now
            if custom_reset_timeout:
                self.dynamic_reset_timeout = custom_reset_timeout
            else:
                self.dynamic_reset_timeout = self.reset_timeout

            if new_state == CircuitState.CLOSED:
                self.failure_count = 0
                self.success_count = 0
            elif new_state == CircuitState.HALF_OPEN:
                self.success_count = 0

            await self._set_redis_state(
                new_state,
                0 if new_state == CircuitState.CLOSED else self.failure_count,
                0 if new_state == CircuitState.HALF_OPEN else self.success_count,
                now,
            )
            update_breaker_metric(self.name, new_state.value)

    async def call(
        self,
        func: Callable[..., Coroutine[Any, Any, Any]],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        async with self._lock:
            state, fail_cnt, succ_cnt, last_change = await self._get_redis_state()
            now = time.time()

            if state == CircuitState.OPEN:
                effective_timeout = getattr(
                    self, "dynamic_reset_timeout", self.reset_timeout
                )
                if now - last_change > effective_timeout:
                    await self._transition(CircuitState.HALF_OPEN)
                    state = CircuitState.HALF_OPEN
                else:
                    raise CircuitBreakerOpenException(
                        f"CircuitBreaker '{self.name}' is OPEN. Fast-failing."
                    )

            if state == CircuitState.HALF_OPEN:
                if self._half_open_trial_active:
                    raise CircuitBreakerOpenException(
                        f"CircuitBreaker '{self.name}' is HALF_OPEN (trial in progress). Fast-failing concurrent request."
                    )
                self._half_open_trial_active = True

        try:
            result = await func(*args, **kwargs)
            async with self._lock:
                state, fail_cnt, succ_cnt, last_change = await self._get_redis_state()
                if state == CircuitState.HALF_OPEN:
                    succ_cnt += 1
                    self.success_count = succ_cnt
                    await self._set_redis_state(state, fail_cnt, succ_cnt, last_change)
                    if succ_cnt >= self.half_open_max_trials:
                        await self._transition(CircuitState.CLOSED)
                elif state == CircuitState.CLOSED:
                    self.failure_count = 0
                    await self._set_redis_state(CircuitState.CLOSED, 0, 0, time.time())
            return result
        except Exception as exc:
            if is_transient_error(exc):
                retry_after = parse_retry_after(exc)
                custom_timeout = (
                    max(self.reset_timeout, retry_after) if retry_after else None
                )

                async with self._lock:
                    (
                        state,
                        fail_cnt,
                        succ_cnt,
                        last_change,
                    ) = await self._get_redis_state()
                    fail_cnt += 1
                    self.failure_count = fail_cnt
                    await self._set_redis_state(state, fail_cnt, succ_cnt, last_change)

                    if state == CircuitState.HALF_OPEN or fail_cnt >= self.fail_max:
                        await self._transition(
                            CircuitState.OPEN, custom_reset_timeout=custom_timeout
                        )
            else:
                logger.debug(
                    f"CircuitBreaker '{self.name}' ignoring non-transient error: {exc}"
                )
            raise
        finally:
            self._half_open_trial_active = False


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
    delay = initial_delay
    last_exception = None
    for attempt in range(1, max_retries + 1):
        try:
            return await func(*args, **kwargs)
        except Exception as exc:
            last_exception = exc
            if not is_transient_error(exc) or attempt == max_retries:
                logger.error(
                    f"Retry exhausted ({attempt}/{max_retries}) for {func.__name__}: {exc}"
                )
                raise
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
        raise
