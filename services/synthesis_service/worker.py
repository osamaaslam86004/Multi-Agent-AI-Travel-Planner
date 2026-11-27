from services.core.config import get_settings

"""
Synthesis & Itinerary Worker: Scatter-Gather Barrier Aggregator and LLM Orchestrator.
Uses State Machine Barrier (GATHERING -> SYNTHESIZING -> DONE), Deadline ZSET with Janitor,
Off-consume-loop bounded semaphore execution, single-call LLM synthesis, PII Redaction,
Traceparent Context Propagation, Structured Logging, and Health Probes.
"""
import asyncio
import logging
import os
import signal

from aiohttp import web
from opentelemetry import trace
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from services.common.db import record_llm_usage, record_trip_event, upsert_trip_result
from services.common.event_bus import EventBus
from services.common.pii_redactor import redact_pii, sanitize_tool_output
from services.common.schemas import (
    CloudEvent,
    SynthesisCompletedPayload,
)
from services.common.telemetry import (
    configure_structured_logging,
    get_tracer,
    set_log_context,
    setup_telemetry,
)
from services.synthesis_service.barrier import BarrierStateMachine
from services.synthesis_service.synthesizer import SynthesisEngine

configure_structured_logging()
logger = logging.getLogger("travelbrain.synthesis_worker")
REDIS_URL = get_settings().redis.url
STREAM_FLIGHTS = "stream:travel:flights:completed"
STREAM_HOTELS = "stream:travel:hotels:completed"
STREAM_WEATHER = "stream:travel:weather:completed"
STREAM_OUT = "stream:travel:synthesis:completed"
CONSUMER_GROUP = "cg-synthesis-service"
HOSTNAME = os.getenv("HOSTNAME") or os.getenv("POD_NAME") or "local-worker"
CONSUMER_NAME = f"synthesis-worker-{HOSTNAME}-{os.getpid()}"
setup_telemetry(service_name="synthesis-service")
tracer = get_tracer("travelbrain.synthesis_worker")
event_bus = EventBus(redis_url=REDIS_URL)
engine = SynthesisEngine()
barrier_sm: BarrierStateMachine | None = None
synthesis_semaphore = asyncio.Semaphore(10)
stop_event = asyncio.Event()
is_healthy = True


async def handle_liveness(request):
    return web.json_response({"status": "UP", "service": "synthesis-worker"})


async def handle_readiness(request):
    if is_healthy and not stop_event.is_set():
        return web.json_response({"status": "READY"})
    return web.json_response({"status": "DRAINING"}, status=503)


async def start_health_server():
    app = web.Application()
    app.router.add_get("/health/live", handle_liveness)
    app.router.add_get("/health/ready", handle_readiness)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", 8080)
    await site.start()
    logger.info("Synthesis worker health probe server listening on port 8080")


async def execute_synthesis(
    correlation_id: str, traceparent: str | None = None
) -> None:
    async with synthesis_semaphore:
        if not barrier_sm:
            return
        data = await barrier_sm.get_barrier_data(correlation_id)
        if not data:
            return
        tenant_id = data.get("tenant_id", "default")
        set_log_context(correlation_id=correlation_id, tenant_id=tenant_id)
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
        raw_flights = data.get("flight_results", "")
        raw_hotels = data.get("hotel_results", "")
        raw_weather = data.get("weather_results", "")
        flight_degraded = data.get("flight_degraded", "false").lower() == "true"
        hotel_degraded = data.get("hotel_degraded", "false").lower() == "true"
        weather_degraded = data.get("weather_degraded", "false").lower() == "true"
        clean_query = redact_pii(raw_query)
        clean_flights = sanitize_tool_output(raw_flights, max_length=3000)
        clean_hotels = sanitize_tool_output(raw_hotels, max_length=3000)
        clean_weather = sanitize_tool_output(raw_weather, max_length=3000)
        # Context propagation for OTel
        carrier = {"traceparent": traceparent} if traceparent else {}
        otel_ctx = TraceContextTextMapPropagator().extract(carrier)
        token = trace.use_span(tracer.start_span("synthesis.execute", context=otel_ctx))
        try:
            itinerary, final_response = await engine.synthesize_plan(
                clean_query,
                clean_flights,
                clean_hotels,
                clean_weather,
                tenant_id=tenant_id,
            )
        finally:
            token.__exit__(None, None, None)
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
    tenant_id = data.get("tenant_id", "default")
    set_log_context(correlation_id=cid, tenant_id=tenant_id)
    if barrier_sm:
        await barrier_sm.init_barrier(
            correlation_id=cid,
            user_query=data.get("user_query", ""),
            user_id=data.get("user_id", "guest"),
            tenant_id=tenant_id,
        )
        claimed = await barrier_sm.try_claim_synthesis(cid)
        if claimed:
            asyncio.create_task(execute_synthesis(cid, event.traceparent))


async def handle_agent_completed(event: CloudEvent, domain: str) -> None:
    data = event.data if isinstance(event.data, dict) else event.data.model_dump()
    cid = data["correlation_id"]
    tenant_id = data.get("tenant_id", "default")
    set_log_context(correlation_id=cid, tenant_id=tenant_id)
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

    def handle_shutdown():
        logger.info("SIGTERM/SIGINT received. Initiating graceful shutdown drain...")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, handle_shutdown)
        except NotImplementedError:
            pass
    asyncio.create_task(start_health_server())
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
        await event_bus.close()
        logger.info("Synthesis worker shutdown complete.")


if __name__ == "__main__":
    asyncio.run(main())
