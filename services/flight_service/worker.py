from services.core.config import get_settings

"""
Flight Agent background worker subscribing to Redis Streams with OpenTelemetry tracing,
Structured Logging, Signal-based Graceful Shutdown, and HTTP Health Probes.
"""
import asyncio
import logging
import os
import signal

import redis.asyncio as aioredis
from aiohttp import web
from opentelemetry import trace
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

from services.common.event_bus import EventBus
from services.common.schemas import (
    CloudEvent,
    FlightResultPayload,
    PlanningInitiatedPayload,
)
from services.common.telemetry import (
    configure_structured_logging,
    get_tracer,
    set_log_context,
    setup_telemetry,
)
from services.flight_service.provider import FlightProvider

configure_structured_logging()
logger = logging.getLogger("travelbrain.flight_worker")
REDIS_URL = get_settings().redis.url
STREAM_IN = "stream:travel:planning:initiated"
STREAM_OUT = "stream:travel:flights:completed"
CONSUMER_GROUP = "cg-flight-service"
HOSTNAME = os.getenv("HOSTNAME") or os.getenv("POD_NAME") or "local-worker"
CONSUMER_NAME = f"flight-worker-{HOSTNAME}-{os.getpid()}"
setup_telemetry(service_name="flight-service")
tracer = get_tracer("travelbrain.flight_worker")
event_bus = EventBus(redis_url=REDIS_URL)
provider = FlightProvider(redis_url=REDIS_URL)
stop_event = asyncio.Event()
is_healthy = True


async def handle_liveness(request):
    return web.json_response({"status": "UP", "service": "flight-worker"})


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
    logger.info("Flight worker health probe server listening on port 8080")


async def handle_planning_initiated(
    event: CloudEvent[PlanningInitiatedPayload],
) -> None:
    data = event.data
    correlation_id = (
        data.get("correlation_id") if isinstance(data, dict) else data.correlation_id
    )
    tenant_id = (
        data.get("tenant_id", "default")
        if isinstance(data, dict)
        else getattr(data, "tenant_id", "default")
    )
    user_id = (
        data.get("user_id", "unknown")
        if isinstance(data, dict)
        else getattr(data, "user_id", "unknown")
    )
    set_log_context(correlation_id=correlation_id, tenant_id=tenant_id)
    query = data.get("user_query") if isinstance(data, dict) else data.user_query
    destination = (
        data.get("destination")
        if isinstance(data, dict)
        else getattr(data, "destination", None)
    )
    departure_city = (
        data.get("departure_city")
        if isinstance(data, dict)
        else getattr(data, "departure_city", None)
    )
    dates = (
        data.get("dates") if isinstance(data, dict) else getattr(data, "dates", None)
    )
    logger.info(
        f"Processing flight search for trip {correlation_id} (query: '{query}', dep: '{departure_city}', dest: '{destination}')"
    )
    carrier = {"traceparent": event.traceparent} if event.traceparent else {}
    otel_ctx = TraceContextTextMapPropagator().extract(carrier)
    token = trace.use_span(tracer.start_span("flight_worker.search", context=otel_ctx))
    try:
        await event_bus.publish_progress(
            correlation_id,
            {
                "stage": "flights_in_progress",
                "message": "Flight Agent is analyzing routes, airlines, and schedule options...",
                "percentage": 25,
            },
        )
        try:
            provider_res = await provider.search_flights(
                query=query,
                departure_city=departure_city,
                destination=destination,
                dates=dates,
            )
            out_event = CloudEvent[FlightResultPayload](
                source="/services/flight-agent",
                type="com.travelbrain.flights.completed.v1",
                subject=correlation_id,
                traceparent=event.traceparent,
                data=FlightResultPayload(
                    correlation_id=correlation_id,
                    user_id=user_id,
                    tenant_id=tenant_id,
                    user_query=query,
                    success=True,
                    results=provider_res.text,
                    source=provider_res.source,
                    degraded=provider_res.degraded,
                    cached=False,
                ),
            )
            await event_bus.publish(STREAM_OUT, out_event)
            await event_bus.publish_progress(
                correlation_id,
                {
                    "stage": "flights_completed",
                    "message": "Flight recommendations compiled successfully.",
                    "percentage": 40,
                    "degraded": provider_res.degraded,
                },
            )
            logger.info(f"Published flight results for trip {correlation_id}")
        except (
            aioredis.RedisError,
            TimeoutError,
            OSError,
            RuntimeError,
            ValueError,
        ) as exc:
            logger.error(f"Flight search failed for trip {correlation_id}: {exc}")
            out_event = CloudEvent[FlightResultPayload](
                source="/services/flight-agent",
                type="com.travelbrain.flights.completed.v1",
                subject=correlation_id,
                traceparent=event.traceparent,
                data=FlightResultPayload(
                    correlation_id=correlation_id,
                    user_id=user_id,
                    tenant_id=tenant_id,
                    success=False,
                    results="Flight information currently unavailable.",
                    source="error",
                    degraded=True,
                    error=str(exc),
                ),
            )
            await event_bus.publish(STREAM_OUT, out_event)
    finally:
        token.__exit__(None, None, None)


async def main():
    await event_bus.connect()
    loop = asyncio.get_running_loop()

    def handle_shutdown():
        logger.info("SIGTERM/SIGINT received. Initiating flight worker drain...")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, handle_shutdown)
        except NotImplementedError:
            pass
    asyncio.create_task(start_health_server())
    try:
        await event_bus.consume(
            stream_name=STREAM_IN,
            group_name=CONSUMER_GROUP,
            consumer_name=CONSUMER_NAME,
            handler=handle_planning_initiated,
            stop_event=stop_event,
        )
    finally:
        await provider.close()
        await event_bus.close()
        logger.info("Flight worker shutdown complete.")


if __name__ == "__main__":
    asyncio.run(main())
