"""
Resilient Multi-Provider Fallback Chain Orchestrator with OpenTelemetry Instrumentation,
Circuit Breaking, and Priority-Ordered Failover (Groq -> Gemini -> Local Hugging Face).
"""

import logging
import time
from collections.abc import Sequence
from typing import Any

from langchain_core.messages import BaseMessage
from opentelemetry.trace import StatusCode

from services.common.llm_provider import (
    BaseLLMProvider,
    GeminiLLMProvider,
    GroqLLMProvider,
    LLMResult,
    LocalHuggingFaceProvider,
)
from services.common.resilience import CircuitBreaker
from services.common.telemetry import get_tracer

logger = logging.getLogger("travelbrain.resilient_chain")
tracer = get_tracer("travelbrain.llm")


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
    ):
        if providers:
            self.providers = list(providers)
        else:
            # Default priority-ordered fallback chain
            self.providers = [
                GroqLLMProvider(),
                GeminiLLMProvider(),
                LocalHuggingFaceProvider(),
            ]

        self.enable_circuit_breaker = enable_circuit_breaker
        self.circuit_breakers: dict[str, CircuitBreaker] = {
            "groq": CircuitBreaker("GroqLLMBreaker", fail_max=3, reset_timeout=45.0),
            "gemini": CircuitBreaker(
                "GeminiLLMBreaker", fail_max=3, reset_timeout=45.0
            ),
            "local_huggingface": CircuitBreaker(
                "LocalLLMBreaker", fail_max=5, reset_timeout=15.0
            ),
        }

    async def generate(
        self,
        messages: list[BaseMessage],
        temperature: float = 0.3,
        **kwargs: Any,
    ) -> LLMResult:
        """
        Executes generation across the fallback chain in strict priority order.
        Instruments execution with OpenTelemetry spans and token tracking.
        """
        last_error: Exception | None = None
        attempt_history: list[dict[str, Any]] = []

        with tracer.start_as_current_span("llm.request") as root_span:
            for index, provider in enumerate(self.providers, start=1):
                provider_name = provider.provider_name
                model_name = provider.model_name

                # Check if provider is available
                if not provider.is_available():
                    logger.info(
                        f"Skipping provider {provider_name} (credentials or dependencies missing)."
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

                        # Record successful metrics in OpenTelemetry
                        span.set_attribute(
                            "llm.tokens.prompt",
                            result.token_usage.get("prompt_tokens", 0),
                        )
                        span.set_attribute(
                            "llm.tokens.completion",
                            result.token_usage.get("completion_tokens", 0),
                        )
                        span.set_attribute(
                            "llm.tokens.total",
                            result.token_usage.get("total_tokens", 0),
                        )
                        span.set_attribute("llm.latency_ms", result.latency_ms)
                        span.set_status(StatusCode.OK)

                        # Set root span summary attributes
                        root_span.set_attribute("llm.selected_provider", provider_name)
                        root_span.set_attribute("llm.selected_model", model_name)
                        root_span.set_attribute(
                            "llm.total_latency_ms", result.latency_ms
                        )
                        root_span.set_attribute(
                            "llm.tokens.total",
                            result.token_usage.get("total_tokens", 0),
                        )
                        root_span.set_status(StatusCode.OK)

                        logger.info(
                            f"Generation SUCCEEDED with {provider_name} "
                            f"(Latency: {result.latency_ms:.1f}ms, "
                            f"Tokens: {result.token_usage.get('total_tokens', 0)})"
                        )
                        return result

                    except Exception as exc:
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

                        span.record_exception(exc)
                        span.set_status(StatusCode.ERROR, str(exc))
                        logger.warning(
                            f"[Tier {index} FAILED] {provider_name} ({model_name}) error: {exc}. "
                            f"Failing over to next available provider..."
                        )

            # If all providers fail
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
        **kwargs: Any,
    ) -> LLMResult:
        """
        Executes structured JSON schema generation across the fallback chain.
        """
        last_error: Exception | None = None
        attempt_history: list[dict[str, Any]] = []

        with tracer.start_as_current_span("llm.request.structured") as root_span:
            for index, provider in enumerate(self.providers, start=1):
                provider_name = provider.provider_name
                model_name = provider.model_name

                if not provider.is_available():
                    continue

                breaker = self.circuit_breakers.get(provider_name)
                start_time = time.perf_counter()

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

                        span.set_attribute(
                            "llm.tokens.total",
                            result.token_usage.get("total_tokens", 0),
                        )
                        span.set_attribute("llm.latency_ms", result.latency_ms)
                        span.set_status(StatusCode.OK)

                        root_span.set_attribute("llm.selected_provider", provider_name)
                        root_span.set_status(StatusCode.OK)
                        return result

                    except Exception as exc:
                        last_error = exc
                        attempt_history.append(
                            {"provider": provider_name, "error": str(exc)}
                        )
                        span.record_exception(exc)
                        span.set_status(StatusCode.ERROR, str(exc))
                        logger.warning(
                            f"[Tier {index} Structured FAILED] {provider_name} error: {exc}. Failing over..."
                        )

            root_span.set_status(StatusCode.ERROR, "All structured providers failed")
            summary = "; ".join(
                f"{a['provider']}: {a['error']}" for a in attempt_history
            )
            raise RuntimeError(
                f"ResilientLLMChain structured generation exhausted all providers: [{summary}]"
            ) from last_error
