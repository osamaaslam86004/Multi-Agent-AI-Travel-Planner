"""
Resilient Multi-Provider Fallback Chain Orchestrator with OpenTelemetry Instrumentation,
Shared Redis Circuit Breakers, and Priority-Ordered Failover (Groq -> Gemini -> Local Hugging Face).
"""

import logging
import time
from collections.abc import Sequence
from typing import Any

import httpx
from langchain_core.messages import BaseMessage
from opentelemetry.trace import StatusCode

from services.common.llm_provider import (
    BaseLLMProvider,
    GeminiLLMProvider,
    GroqLLMProvider,
    LLMResult,
    LocalHuggingFaceProvider,
)
from services.common.resilience import (
    CircuitBreaker,
    CircuitBreakerOpenException,
)
from services.common.telemetry import get_tracer, record_llm_metrics

logger = logging.getLogger("travelbrain.resilient_chain")
tracer = get_tracer("travelbrain.llm")


def calculate_cost_estimate(
    provider_name: str, model_name: str, prompt_tokens: int, completion_tokens: int
) -> float:
    """Calculate estimated cost in USD based on provider pricing."""
    p_lower = provider_name.lower()
    if "groq" in p_lower:
        return (prompt_tokens * 0.59 / 1_000_000.0) + (
            completion_tokens * 0.79 / 1_000_000.0
        )
    elif "gemini" in p_lower:
        return (prompt_tokens * 0.15 / 1_000_000.0) + (
            completion_tokens * 0.60 / 1_000_000.0
        )
    return 0.0


class ResilientLLMChain:
    """
    Orchestrates a 3-tier resilient fallback chain:
    1. Primary: GroqLLMProvider (High-speed cloud inference)
    2. Cloud Fallback: GeminiLLMProvider (Google Cloud AI)
    3. Air-Gapped Fallback: LocalHuggingFaceProvider (<12GB VRAM consumer footprint)
    """

    def __init__(
        self,
        providers: Sequence[BaseLLMProvider] | None = None,
        enable_circuit_breaker: bool = True,
        redis_client: Any = None,
    ):
        if providers:
            self.providers = list(providers)
        else:
            self.providers = [
                GroqLLMProvider(),
                GeminiLLMProvider(),
                LocalHuggingFaceProvider(),
            ]
        self.enable_circuit_breaker = enable_circuit_breaker
        self.redis_client = redis_client
        self.circuit_breakers: dict[str, CircuitBreaker] = {
            "groq": CircuitBreaker(
                "GroqLLMBreaker",
                fail_max=3,
                reset_timeout=45.0,
                redis_client=redis_client,
            ),
            "gemini": CircuitBreaker(
                "GeminiLLMBreaker",
                fail_max=3,
                reset_timeout=45.0,
                redis_client=redis_client,
            ),
            "local_huggingface": CircuitBreaker(
                "LocalLLMBreaker",
                fail_max=5,
                reset_timeout=15.0,
                redis_client=redis_client,
            ),
        }

    async def generate(
        self,
        messages: list[BaseMessage],
        temperature: float = 0.3,
        tenant_id: str = "default",
        **kwargs: Any,
    ) -> LLMResult:
        last_error: Exception | None = None
        attempt_history: list[dict[str, Any]] = []
        with tracer.start_as_current_span("llm.request") as root_span:
            for index, provider in enumerate(self.providers, start=1):
                provider_name = provider.provider_name
                model_name = provider.model_name
                if not provider.is_available():
                    logger.info(
                        f"Skipping provider {provider_name} (unreachable or unconfigured)."
                    )
                    continue
                breaker = self.circuit_breakers.get(provider_name)
                start_time = time.perf_counter()
                with tracer.start_as_current_span(
                    f"llm.provider.{provider_name}"
                ) as span:
                    span.set_attribute("llm.provider", provider_name)
                    span.set_attribute("llm.model", model_name)
                    span.set_attribute("llm.tier_priority", index)
                    try:
                        logger.info(
                            f"[Tier {index}] Attempting generation with {provider_name} ({model_name})..."
                        )
                        if self.enable_circuit_breaker and breaker:
                            result = await breaker.call(
                                provider.generate,
                                messages=messages,
                                temperature=temperature,
                                **kwargs,
                            )
                        else:
                            result = await provider.generate(
                                messages=messages,
                                temperature=temperature,
                                **kwargs,
                            )
                        prompt_tokens = result.token_usage.get("prompt_tokens", 0)
                        completion_tokens = result.token_usage.get(
                            "completion_tokens", 0
                        )
                        total_tokens = result.token_usage.get("total_tokens", 0)
                        cost_est = calculate_cost_estimate(
                            provider_name, model_name, prompt_tokens, completion_tokens
                        )
                        span.set_attribute("llm.tokens.prompt", prompt_tokens)
                        span.set_attribute("llm.tokens.completion", completion_tokens)
                        span.set_attribute("llm.tokens.total", total_tokens)
                        span.set_attribute("llm.cost_usd", cost_est)
                        span.set_attribute("llm.latency_ms", result.latency_ms)
                        if span and hasattr(span, "set_status"):
                            span.set_status(StatusCode.OK)
                        root_span.set_attribute("llm.selected_provider", provider_name)
                        root_span.set_attribute("llm.selected_model", model_name)
                        root_span.set_attribute(
                            "llm.total_latency_ms", result.latency_ms
                        )
                        root_span.set_attribute("llm.tokens.total", total_tokens)
                        if root_span and hasattr(root_span, "set_status"):
                            root_span.set_status(StatusCode.OK)
                        record_llm_metrics(
                            tenant_id=tenant_id,
                            provider=provider_name,
                            model=model_name,
                            prompt_tokens=prompt_tokens,
                            completion_tokens=completion_tokens,
                            total_tokens=total_tokens,
                            cost_estimate=cost_est,
                        )
                        logger.info(
                            f"Generation SUCCEEDED with {provider_name} "
                            f"(Latency: {result.latency_ms:.1f}ms, "
                            f"Tokens: {total_tokens}, Cost: ${cost_est:.6f})"
                        )
                        return result
                    except (
                        httpx.HTTPError,
                        CircuitBreakerOpenException,
                        RuntimeError,
                        ValueError,
                        OSError,
                        TimeoutError,
                    ) as exc:
                        latency_ms = (time.perf_counter() - start_time) * 1000.0
                        last_error = exc
                        attempt_history.append(
                            {
                                "provider": provider_name,
                                "model": model_name,
                                "error": str(exc),
                                "latency_ms": latency_ms,
                            }
                        )
                        if span and hasattr(span, "record_exception"):
                            span.record_exception(exc)
                        if span and hasattr(span, "set_status"):
                            span.set_status(StatusCode.ERROR, str(exc))
                        logger.warning(
                            f"[Tier {index} FAILED] {provider_name} ({model_name}) error: {exc}. "
                            f"Failing over to next available provider..."
                        )
            if root_span and hasattr(root_span, "set_status"):
                root_span.set_status(
                    StatusCode.ERROR, "All LLM providers in fallback chain failed"
                )
            summary = "; ".join(
                f"{a['provider']}: {a['error']}" for a in attempt_history
            )
            raise RuntimeError(
                f"ResilientLLMChain exhausted all providers without success. Attempt summary: [{summary}]"
            ) from last_error

    async def generate_structured(
        self,
        messages: list[BaseMessage],
        response_format: dict[str, Any],
        temperature: float = 0.1,
        tenant_id: str = "default",
        **kwargs: Any,
    ) -> LLMResult:
        last_error: Exception | None = None
        attempt_history: list[dict[str, Any]] = []
        with tracer.start_as_current_span("llm.request.structured") as root_span:
            for index, provider in enumerate(self.providers, start=1):
                provider_name = provider.provider_name
                model_name = provider.model_name
                if not provider.is_available():
                    continue
                breaker = self.circuit_breakers.get(provider_name)
                time.perf_counter()
                with tracer.start_as_current_span(
                    f"llm.provider.{provider_name}.structured"
                ) as span:
                    span.set_attribute("llm.provider", provider_name)
                    span.set_attribute("llm.model", model_name)
                    span.set_attribute("llm.tier_priority", index)
                    try:
                        logger.info(
                            f"[Tier {index} Structured] Attempting generation with {provider_name}..."
                        )
                        if self.enable_circuit_breaker and breaker:
                            result = await breaker.call(
                                provider.generate_structured,
                                messages=messages,
                                response_format=response_format,
                                temperature=temperature,
                                **kwargs,
                            )
                        else:
                            result = await provider.generate_structured(
                                messages=messages,
                                response_format=response_format,
                                temperature=temperature,
                                **kwargs,
                            )
                        prompt_tokens = result.token_usage.get("prompt_tokens", 0)
                        completion_tokens = result.token_usage.get(
                            "completion_tokens", 0
                        )
                        total_tokens = result.token_usage.get("total_tokens", 0)
                        cost_est = calculate_cost_estimate(
                            provider_name, model_name, prompt_tokens, completion_tokens
                        )
                        span.set_attribute("llm.tokens.total", total_tokens)
                        span.set_attribute("llm.latency_ms", result.latency_ms)
                        if span and hasattr(span, "set_status"):
                            span.set_status(StatusCode.OK)
                        root_span.set_attribute("llm.selected_provider", provider_name)
                        if root_span and hasattr(root_span, "set_status"):
                            root_span.set_status(StatusCode.OK)
                        record_llm_metrics(
                            tenant_id=tenant_id,
                            provider=provider_name,
                            model=model_name,
                            prompt_tokens=prompt_tokens,
                            completion_tokens=completion_tokens,
                            total_tokens=total_tokens,
                            cost_estimate=cost_est,
                        )
                        return result
                    except (
                        httpx.HTTPError,
                        CircuitBreakerOpenException,
                        RuntimeError,
                        ValueError,
                        OSError,
                        TimeoutError,
                    ) as exc:
                        last_error = exc
                        attempt_history.append(
                            {"provider": provider_name, "error": str(exc)}
                        )
                        if span and hasattr(span, "record_exception"):
                            span.record_exception(exc)
                        if span and hasattr(span, "set_status"):
                            span.set_status(StatusCode.ERROR, str(exc))
                        logger.warning(
                            f"[Tier {index} Structured FAILED] {provider_name} error: {exc}. Failing over..."
                        )
            if root_span and hasattr(root_span, "set_status"):
                root_span.set_status(
                    StatusCode.ERROR, "All structured providers failed"
                )
            summary = "; ".join(
                f"{a['provider']}: {a['error']}" for a in attempt_history
            )
            raise RuntimeError(
                f"ResilientLLMChain structured generation exhausted all providers: [{summary}]"
            ) from last_error
