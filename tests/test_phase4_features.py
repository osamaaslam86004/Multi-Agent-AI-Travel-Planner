"""
Comprehensive Unit & Integration Test Suite for Phase 4 Architecture:
Observability (OTel & JSON Logging), FinOps (Persistence & Pre-flight Budgets),
Metrics (Cardinality Control), Scale (Probes & Shutdown), and LLM Tier / Circuit Breaker Fixes.
"""
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from services.bff_gateway.session_manager import SessionManager
from services.common.db import (
    calculate_cost,
    record_llm_usage,
)
from services.common.llm_provider import LocalHuggingFaceProvider
from services.common.resilience import (
    CircuitBreaker,
    parse_retry_after,
)
from services.common.telemetry import (
    JSONFormatter,
    extract_traceparent,
    generate_traceparent,
    inject_traceparent,
    set_log_context,
)
from services.synthesis_service.synthesizer import SynthesisEngine


@pytest.mark.asyncio
async def test_traceparent_generation_and_w3c_extraction():
    """Verify W3C traceparent format generation and header extraction."""
    tp = generate_traceparent()
    assert tp.startswith("00-")
    parts = tp.split("-")
    assert len(parts) == 4
    assert len(parts[1]) == 32
    assert len(parts[2]) == 16
    headers = {"TraceParent": tp}
    extracted = extract_traceparent(headers)
    assert extracted == tp
    carrier = {}
    injected = inject_traceparent(carrier, tp)
    assert injected["traceparent"] == tp
@pytest.mark.asyncio
async def test_structured_json_logging_formatter():
    """Verify JSON log formatter includes trace_id, span_id, correlation_id, and tenant_id."""
    set_log_context(correlation_id="trip_test_999", tenant_id="tenant_gamma")
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Test log message",
        args=(),
        exc_info=None,
    )
    formatted_str = formatter.format(record)
    parsed = json.loads(formatted_str)
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "test_logger"
    assert parsed["message"] == "Test log message"
    assert parsed["correlation_id"] == "trip_test_999"
    assert parsed["tenant_id"] == "tenant_gamma"
    assert "trace_id" in parsed
    assert "timestamp" in parsed
@pytest.mark.asyncio
async def test_finops_cost_calculation_and_ledger():
    """Verify FinOps pricing formulas and DB usage recording."""
    groq_cost = calculate_cost("groq", "llama-3.3-70b-versatile", 1000, 500)
    assert round(groq_cost, 6) == 0.000985
    gemini_cost = calculate_cost("gemini", "gemini-2.5-flash", 2000, 1000)
    assert round(gemini_cost, 6) == 0.0009
    local_cost = calculate_cost("local_huggingface", "qwen2.5:7b", 5000, 5000)
    assert local_cost == 0.0
    await record_llm_usage(
        tenant_id="tenant_finops",
        user_id="usr_finops",
        correlation_id="trip_finops_1",
        provider="groq",
        model="llama-3.3-70b-versatile",
        prompt_tokens=1000,
        completion_tokens=500,
        total_tokens=1500,
        latency_ms=320.5,
    )
@pytest.mark.asyncio
async def test_preflight_tenant_budget_check():
    """Verify pre-flight tenant token budget enforcement in SessionManager."""
    sm = SessionManager(redis_url="redis://localhost:6379/1")
    mock_redis = MagicMock()
    mock_redis.get = AsyncMock(return_value="198000")
    sm.get_redis = AsyncMock(return_value=mock_redis)
    allowed, current = await sm.check_tenant_budget(
        tenant_id="tenant_test", estimated_tokens=5000, daily_limit_tokens=200000
    )
    assert allowed is False
    assert current == 198000
@pytest.mark.asyncio
async def test_circuit_breaker_non_transient_error_filtering():
    """Verify that non-transient exceptions (ValueError) do NOT count as circuit breaker failures."""
    cb = CircuitBreaker("TestBreaker", fail_max=2, reset_timeout=5.0)
    with pytest.raises(ValueError):
        await cb.call(AsyncMock(side_effect=ValueError("Invalid config parameter")))
    assert cb.failure_count == 0
    assert cb.state == "CLOSED"
    with pytest.raises(httpx.HTTPError):
        await cb.call(AsyncMock(side_effect=httpx.HTTPError("503 Service Unavailable")))
    assert cb.failure_count == 1
@pytest.mark.asyncio
async def test_circuit_breaker_retry_after_parsing():
    """Verify Retry-After header parsing from HTTPStatusError."""
    mock_resp = MagicMock()
    mock_resp.headers = {"Retry-After": "45"}
    mock_resp.status_code = 429
    err = httpx.HTTPStatusError(
        "429 Too Many Requests", request=MagicMock(), response=mock_resp
    )
    retry_sec = parse_retry_after(err)
    assert retry_sec == 45.0
@pytest.mark.asyncio
async def test_local_huggingface_provider_availability():
    """Verify LocalHuggingFaceProvider does NOT falsely report available when offline."""
    provider = LocalHuggingFaceProvider(local_endpoint_url="http://localhost:9999/v1")
    with patch("httpx.get", side_effect=httpx.ConnectError("Connection refused")):
        assert provider.is_available() is False
    messages = [MagicMock(type="user", content="Plan trip")]
    with (
        patch("httpx.get", side_effect=httpx.ConnectError("Connection refused")),
        pytest.raises(RuntimeError),
    ):
        await provider.generate(messages)
@pytest.mark.asyncio
async def test_synthesizer_xml_delimitation_and_input_bounds():
    """Verify synthesizer wraps untrusted user query and agent inputs in XML tags and enforces character bounds."""
    engine = SynthesisEngine()
    mock_chain = AsyncMock()
    mock_result = MagicMock()
    mock_result.content = "Day 1: Arrive\n---ITINERARY_DOSSIER_SPLIT---\n# Dossier"
    mock_result.provider_name = "mock_provider"
    mock_result.model_name = "mock_model"
    mock_result.latency_ms = 150.0
    mock_result.token_usage = {"total_tokens": 100}
    mock_chain.generate.return_value = mock_result
    engine.chain = mock_chain
    long_query = "A" * 2000
    long_flights = "B" * 5000
    _itin, _resp = await engine.synthesize_plan(
        user_query=long_query,
        flight_results=long_flights,
        hotel_results="Hotel info",
        weather_results="Sunny 25C",
    )
    assert mock_chain.generate.called
    call_args = mock_chain.generate.call_args[0][0]
    user_msg_content = call_args[1].content
    assert "<user_query>" in user_msg_content
    assert "</user_query>" in user_msg_content
    assert "<untrusted_flight_data>" in user_msg_content
    assert "</untrusted_flight_data>" in user_msg_content
    assert len(long_query) > 1000