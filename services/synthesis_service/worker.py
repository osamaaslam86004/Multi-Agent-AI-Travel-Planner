"""
Synthesis & Itinerary Worker: Scatter-Gather Barrier Aggregator and LLM Orchestrator.
Uses State Machine Barrier (GATHERING -> SYNTHESIZING -> DONE), Deadline ZSET with Janitor,
Off-consume-loop bounded semaphore execution, single-call LLM synthesis, and PII Redaction.
"""

import asyncio
import logging
import os
import signal

from services.common.db import record_llm_usage, record_trip_event, upsert_trip_result
from services.common.event_bus import EventBus
from services.common.pii_redactor import redact_pii, sanitize_tool_output
from services.common.schemas import (
    CloudEvent,
    SynthesisCompletedPayload,
)
from services.synthesis_service.barrier import BarrierStateMachine
from services.synthesis_service.synthesizer import SynthesisEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("travelbrain.synthesis_worker")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
STREAM_FLIGHTS = "stream:travel:flights:completed"
STREAM_HOTELS = "stream:travel:hotels:completed"
STREAM_WEATHER = "stream:travel:weather:completed"
STREAM_OUT = "stream:travel:synthesis:completed"
CONSUMER_GROUP = "cg-synthesis-service"
HOSTNAME = os.getenv("HOSTNAME") or os.getenv("POD_NAME") or "local-worker"
CONSUMER_NAME = f"synthesis-worker-{HOSTNAME}-{os.getpid()}"

event_bus = EventBus(redis_url=REDIS_URL)
engine = SynthesisEngine()
barrier_sm: BarrierStateMachine | None = None
synthesis_semaphore = asyncio.Semaphore(10)  # Bounded execution off the consume loop
stop_event = asyncio.Event()


async def execute_synthesis(
    correlation_id: str, traceparent: str | None = None
) -> None:
    """
    Off-consume-loop synthesis runner bounded by semaphore.
    Executes single-call LLM synthesis pass, publishes completion event, and records state.
    """
    async with synthesis_semaphore:
        if not barrier_sm:
            return

        data = await barrier_sm.get_barrier_data(correlation_id)
        if not data:
            return

        logger.info(f"Executing off-loop synthesis for trip '{correlation_id}'")

        await event_bus.publish_progress(
            correlation_id,
            {
                "stage": "synthesis_in_progress",
                "message": "Synthesizing multi-agent intelligence into executive trip dossier...",
                "percentage": 75,
            },
        )

        raw_query = data.get("user_query", "")
        user_id = data.get("user_id", "guest")
        tenant_id = data.get("tenant_id", "default")
        raw_flights = data.get("flight_results", "")
        raw_hotels = data.get("hotel_results", "")
        raw_weather = data.get("weather_results", "")
        flight_degraded = data.get("flight_degraded", "false").lower() == "true"
        hotel_degraded = data.get("hotel_degraded", "false").lower() == "true"
        weather_degraded = data.get("weather_degraded", "false").lower() == "true"

        # Redact PII and sanitize inputs
        clean_query = redact_pii(raw_query)
        clean_flights = sanitize_tool_output(raw_flights, max_length=3000)
        clean_hotels = sanitize_tool_output(raw_hotels, max_length=3000)
        clean_weather = sanitize_tool_output(raw_weather, max_length=3000)

        # Single LLM call pass (llm_calls = 1)
        itinerary, final_response = await engine.synthesize_plan(
            clean_query, clean_flights, clean_hotels, clean_weather
        )

        out_payload = SynthesisCompletedPayload(
            correlation_id=correlation_id,
            user_id=user_id,
            tenant_id=tenant_id,
            user_query=clean_query,
            flight_results=clean_flights,
            hotel_results=clean_hotels,
            weather_results=clean_weather,
            itinerary=itinerary,
            final_response=final_response,
            flight_degraded=flight_degraded,
            hotel_degraded=hotel_degraded,
            weather_degraded=weather_degraded,
            llm_calls=1,
        )

        out_event = CloudEvent[SynthesisCompletedPayload](
            source="/services/synthesis-service",
            type="com.travelbrain.synthesis.completed.v1",
            subject=correlation_id,
            traceparent=traceparent,
            data=out_payload,
        )

        await event_bus.publish(STREAM_OUT, out_event)

        # Update per-trip progress stream
        await event_bus.publish_progress(
            correlation_id,
            {
                "stage": "completed",
                "message": "Trip planning complete!",
                "percentage": 100,
                "final_response": final_response,
                "itinerary": itinerary,
                "degraded": flight_degraded or hotel_degraded or weather_degraded,
            },
        )

        # Upsert into Postgres DB / State store idempotently
        await upsert_trip_result(
            tenant_id=tenant_id,
            user_id=user_id,
            correlation_id=correlation_id,
            user_query=clean_query,
            flight_results=clean_flights,
            hotel_results=clean_hotels,
            weather_results=clean_weather,
            itinerary=itinerary,
            final_response=final_response,
            flight_degraded=flight_degraded,
            hotel_degraded=hotel_degraded,
            weather_degraded=weather_degraded,
        )

        await record_trip_event(
            tenant_id=tenant_id,
            correlation_id=correlation_id,
            event_type="com.travelbrain.synthesis.completed.v1",
            payload=out_payload.model_dump(),
        )

        # Record token usage
        last_llm = engine.last_result
        if last_llm:
            await record_llm_usage(
                tenant_id=tenant_id,
                user_id=user_id,
                correlation_id=correlation_id,
                provider=last_llm.provider_name,
                model=last_llm.model_name,
                prompt_tokens=last_llm.token_usage.get("prompt_tokens", 0),
                completion_tokens=last_llm.token_usage.get("completion_tokens", 0),
                total_tokens=last_llm.token_usage.get("total_tokens", 0),
                latency_ms=last_llm.latency_ms,
            )

        if barrier_sm:
            await barrier_sm.mark_done(correlation_id)

        logger.info(f"Synthesis completed successfully for trip '{correlation_id}'")


async def handle_planning_initiated(event: CloudEvent) -> None:
    data = event.data if isinstance(event.data, dict) else event.data.model_dump()
    cid = data["correlation_id"]
    if barrier_sm:
        await barrier_sm.init_barrier(
            correlation_id=cid,
            user_query=data.get("user_query", ""),
            user_id=data.get("user_id", "guest"),
            tenant_id=data.get("tenant_id", "default"),
        )
        claimed = await barrier_sm.try_claim_synthesis(cid)
        if claimed:
            asyncio.create_task(execute_synthesis(cid, event.traceparent))


async def handle_agent_completed(event: CloudEvent, domain: str) -> None:
    data = event.data if isinstance(event.data, dict) else event.data.model_dump()
    cid = data["correlation_id"]
    if barrier_sm:
        await barrier_sm.record_agent_result(
            correlation_id=cid,
            domain=domain,
            results=data.get("results", ""),
            source=data.get("source", "unknown"),
            degraded=data.get("degraded", False),
        )
        claimed = await barrier_sm.try_claim_synthesis(cid)
        if claimed:
            asyncio.create_task(execute_synthesis(cid, event.traceparent))


async def janitor_loop() -> None:
    """Background janitor scanning for timed-out barriers every 1 second."""
    while not stop_event.is_set():
        try:
            if barrier_sm:
                expired_cids = await barrier_sm.check_expired_barriers()
                for cid in expired_cids:
                    asyncio.create_task(execute_synthesis(cid))
        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            logger.debug(f"Janitor loop scan exception: {exc}")
        await asyncio.sleep(1.0)


async def main():
    global barrier_sm
    await event_bus.connect()
    barrier_sm = BarrierStateMachine(event_bus.client, default_deadline_seconds=15.0)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

    janitor_task = asyncio.create_task(janitor_loop())

    try:
        await asyncio.gather(
            event_bus.consume(
                "stream:travel:planning:initiated",
                "cg-synthesis-init",
                f"{CONSUMER_NAME}-init",
                handle_planning_initiated,
                stop_event=stop_event,
            ),
            event_bus.consume(
                STREAM_FLIGHTS,
                CONSUMER_GROUP,
                f"{CONSUMER_NAME}-fl",
                lambda evt: handle_agent_completed(evt, "flight"),
                stop_event=stop_event,
            ),
            event_bus.consume(
                STREAM_HOTELS,
                CONSUMER_GROUP,
                f"{CONSUMER_NAME}-ht",
                lambda evt: handle_agent_completed(evt, "hotel"),
                stop_event=stop_event,
            ),
            event_bus.consume(
                STREAM_WEATHER,
                CONSUMER_GROUP,
                f"{CONSUMER_NAME}-wt",
                lambda evt: handle_agent_completed(evt, "weather"),
                stop_event=stop_event,
            ),
        )
    finally:
        janitor_task.cancel()


if __name__ == "__main__":
    asyncio.run(main())
