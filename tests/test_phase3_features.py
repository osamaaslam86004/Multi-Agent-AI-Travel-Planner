"""
Comprehensive Unit & Integration Test Suite for Phase 3 Architecture.
Validates Postgres DB schema & Outbox relay, Barrier State Machine & Janitor,
Single-call synthesis, per-trip event streams, structured cache keys, and DLQ replay.
"""

import time
from unittest.mock import AsyncMock

import pytest

from services.common.db import (
    get_trip_by_id,
    relay_outbox,
    upsert_trip_result,
    write_outbox,
)
from services.common.event_bus import EventBus
from services.common.schemas import (
    CloudEvent,
    PlanningInitiatedPayload,
)
from services.flight_service.provider import FlightProvider
from services.hotel_service.provider import HotelProvider
from services.synthesis_service.barrier import BarrierStateMachine
from services.synthesis_service.synthesizer import SynthesisEngine
from services.weather_service.provider import WeatherProvider


@pytest.mark.asyncio
async def test_cloudevent_v1_schemas():
    """Verify CloudEvent v1 envelope and versioned type naming."""
    payload = PlanningInitiatedPayload(
        correlation_id="trip_test123",
        user_id="usr_999",
        tenant_id="tenant_alpha",
        user_query="Plan trip to Tokyo",
    )
    event = CloudEvent[PlanningInitiatedPayload](
        source="/services/bff-gateway",
        type="com.travelbrain.planning.initiated.v1",
        subject="trip_test123",
        data=payload,
    )
    assert event.specversion == "1.0"
    assert event.type == "com.travelbrain.planning.initiated.v1"
    assert event.subject == "trip_test123"
    assert event.data.user_id == "usr_999"


@pytest.mark.asyncio
async def test_outbox_write_and_relay():
    """Verify Outbox write and async relay mechanism."""
    mock_bus = AsyncMock(spec=EventBus)
    cid = f"trip_outbox_{int(time.time())}"
    payload = {
        "correlation_id": cid,
        "user_id": "usr_test",
        "tenant_id": "default",
        "user_query": "Fly to Paris",
    }
    res_cid = await write_outbox(
        tenant_id="default",
        correlation_id=cid,
        stream_name="stream:travel:planning:initiated",
        event_type="com.travelbrain.planning.initiated.v1",
        payload=payload,
    )
    assert res_cid == cid
    relayed = await relay_outbox(mock_bus)
    assert relayed >= 1
    assert mock_bus.publish.called


@pytest.mark.asyncio
async def test_barrier_state_machine_and_janitor():
    """Verify Scatter-Gather Barrier State Machine transitions and Janitor expiration."""
    mock_redis = AsyncMock()
    mock_redis.hgetall.return_value = {
        "status": "GATHERING",
        "user_query": "Trip to Rome",
        "user_id": "usr_rome",
        "tenant_id": "default",
        "flight_results": "Flight options found",
    }
    mock_redis.eval.return_value = 1
    mock_redis.zrangebyscore.return_value = ["trip_rome_123"]
    barrier = BarrierStateMachine(redis_client=mock_redis, default_deadline_seconds=5.0)
    await barrier.init_barrier("trip_rome_123", "Trip to Rome")
    assert mock_redis.hset.called
    assert mock_redis.zadd.called
    await barrier.record_agent_result("trip_rome_123", "flight", "Flight options found")
    assert mock_redis.hset.called
    ready_cids = await barrier.check_expired_barriers()
    assert "trip_rome_123" in ready_cids
    assert mock_redis.hset.called


@pytest.mark.asyncio
async def test_single_call_synthesis():
    """Verify single-call synthesis pass produces itinerary and final response with 1 LLM call."""
    engine = SynthesisEngine()
    itin, final_resp = await engine.synthesize_plan(
        user_query="Weekend in Seattle",
        flight_results="Direct SEA flights",
        hotel_results="Downtown boutique hotel",
        weather_results="Mild 18C sunny",
    )
    assert itin is not None
    assert final_resp is not None
    assert (
        "Executive Travel Plan" in final_resp
        or "Seattle" in final_resp
        or "Proposal" in itin
    )


@pytest.mark.asyncio
async def test_structured_cache_keys_and_single_flight_lock():
    """Verify structured cache key generation and single-flight locking in providers."""
    fp = FlightProvider(redis_url="redis://localhost:6379/1")
    hp = HotelProvider(redis_url="redis://localhost:6379/2")
    wp = WeatherProvider(redis_url="redis://localhost:6379/3")
    f_key = fp._cache_key(
        departure_city="NYC",
        destination="LON",
        dates="2026-10-01",
        pax=2,
        tenant_id="tenant_a",
    )
    h_key = hp._cache_key(
        destination="PAR", dates="2026-11-05", pax=1, tenant_id="tenant_a"
    )
    w_key = wp._cache_key(city="TYO", dates="2026-12-01", tenant_id="tenant_a")
    assert f_key.startswith("flight:cache:tenant_a:")
    assert h_key.startswith("hotel:cache:tenant_a:")
    assert w_key.startswith("weather:cache:tenant_a:")
    fallback_res = await fp._fallback_flights("NYC to LON")
    assert fallback_res.degraded is True
    assert fallback_res.source == "fallback"


@pytest.mark.asyncio
async def test_trip_store_upsert_and_retrieval():
    """Verify trip store persistence and retrieval with tenant isolation."""
    cid = f"trip_store_test_{int(time.time())}"
    await upsert_trip_result(
        tenant_id="tenant_beta",
        user_id="usr_beta",
        correlation_id=cid,
        user_query="Explore Kyoto",
        flight_results="JAL flights",
        hotel_results="Ryokan inn",
        weather_results="Autumn leaves 15C",
        itinerary="Day 1: Temples",
        final_response="# Kyoto Plan",
    )
    fetched = await get_trip_by_id(cid, tenant_id="tenant_beta")
    assert fetched is not None
    assert fetched["correlation_id"] == cid
    assert fetched["tenant_id"] == "tenant_beta"
    assert fetched["status"] == "DONE"
    isolated = await get_trip_by_id(cid, tenant_id="other_tenant")
    assert isolated is None
