"""
Weather Agent background worker subscribing to Redis Streams with OpenTelemetry tracing,
Structured Logging, Signal-based Graceful Shutdown, and HTTP Health Probes.
"""

import asyncio
import logging
import os

from aiohttp import web

from services.common.event_bus import EventBus
from services.common.schemas import (
    CloudEvent,
    PlanningInitiatedPayload,
    WeatherResultPayload,
)
from services.common.telemetry import (
    configure_structured_logging,
    get_tracer,
    set_log_context,
    setup_telemetry,
)
from services.core.config import get_settings
from services.weather_service.provider import WeatherProvider

configure_structured_logging()
logger = logging.getLogger("travelbrain.weather_worker")
REDIS_URL = get_settings().redis.url
STREAM_IN = "stream:travel:planning:initiated"
STREAM_OUT = "stream:travel:weather:completed"
CONSUMER_GROUP = "cg-weather-service"
HOSTNAME = os.getenv("HOSTNAME") or os.getenv("POD_NAME") or "local-worker"
CONSUMER_NAME = f"weather-worker-{HOSTNAME}-{os.getpid()}"
setup_telemetry(service_name="weather-service")
tracer = get_tracer("travelbrain.weather_worker")
event_bus = EventBus(redis_url=REDIS_URL)
provider = WeatherProvider(redis_url=REDIS_URL)
stop_event = asyncio.Event()
is_healthy = True


async def handle_liveness(request):
    return web.json_response({"status": "UP", "service": "weather-worker"})


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
    logger.info("Weather worker health probe server listening on port 8080")


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
    dates = (
        data.get("dates") if isinstance(data, dict) else getattr(data, "dates", None)
    )
    logger.info(
        f"Processing weather search for trip {correlation_id} (query: '{query}', dest: '{destination}')"
    )
    try:
        await event_bus.publish_progress(
            correlation_id,
            {
                "stage": "weather_in_progress",
                "message": "Weather Agent is gathering climate and forecast data...",
                "percentage": 35,
            },
        )
        try:
            # Step 1 (A-6): Call provider.get_weather(...) instead of search_weather
            provider_res = await provider.get_weather(
                query=query, destination=destination, dates=dates
            )
            out_event = CloudEvent[WeatherResultPayload](
                source="/services/weather-agent",
                type="com.travelbrain.weather.completed.v1",
                subject=correlation_id,
                traceparent=event.traceparent,
                data=WeatherResultPayload(
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
                    "stage": "weather_completed",
                    "message": "Weather forecast compiled successfully.",
                    "percentage": 60,
                    "degraded": provider_res.degraded,
                },
            )
            logger.info(f"Published weather results for trip {correlation_id}")
        except Exception as exc:
            logger.error(f"Weather search failed for trip {correlation_id}: {exc}")
            out_event = CloudEvent[WeatherResultPayload](
                source="/services/weather-agent",
                type="com.travelbrain.weather.completed.v1",
                subject=correlation_id,
                traceparent=event.traceparent,
                data=WeatherResultPayload(
                    correlation_id=correlation_id,
                    user_id=user_id,
                    tenant_id=tenant_id,
                    success=False,
                    results="Weather information currently unavailable.",
                    source="error",
                    degraded=True,
                    error=str(exc),
                ),
            )
            await event_bus.publish(STREAM_OUT, out_event)
    except Exception as outer_exc:
        logger.error(f"Error handling weather event: {outer_exc}")
