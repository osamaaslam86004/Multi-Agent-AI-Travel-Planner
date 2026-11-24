from services.core.config import get_settings

"""
Trip Store Persistence Worker subscribing to synthesis completion events
and maintaining read models and audit logs.
"""
import asyncio
import logging
import os
import signal

from aiohttp import web

from services.common.db import record_trip_event, upsert_trip_result
from services.common.event_bus import EventBus
from services.common.schemas import CloudEvent
from services.common.telemetry import (
    configure_structured_logging,
    set_log_context,
    setup_telemetry,
)

configure_structured_logging()
logger = logging.getLogger("travelbrain.trip_store_worker")
REDIS_URL = get_settings().redis.url
STREAM_IN = "stream:travel:synthesis:completed"
CONSUMER_GROUP = "cg-trip-store"
HOSTNAME = os.getenv("HOSTNAME") or os.getenv("POD_NAME") or "local-worker"
CONSUMER_NAME = f"trip-store-{HOSTNAME}-{os.getpid()}"
setup_telemetry(service_name="trip-store-service")
event_bus = EventBus(redis_url=REDIS_URL)
stop_event = asyncio.Event()
is_healthy = True
async def handle_liveness(request):
    return web.json_response({"status": "UP", "service": "trip-store-worker"})
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
    logger.info("Trip store worker health probe server listening on port 8080")
async def handle_synthesis_completed(event: CloudEvent) -> None:
    data = event.data if isinstance(event.data, dict) else event.data.model_dump()
    cid = data["correlation_id"]
    user_id = data.get("user_id", "guest")
    tenant_id = data.get("tenant_id", "default")
    user_query = data.get("user_query", "")
    flight_results = data.get("flight_results", "")
    hotel_results = data.get("hotel_results", "")
    weather_results = data.get("weather_results", "")
    itinerary = data.get("itinerary", "")
    final_response = data.get("final_response", "")
    flight_degraded = data.get("flight_degraded", False)
    hotel_degraded = data.get("hotel_degraded", False)
    weather_degraded = data.get("weather_degraded", False)
    set_log_context(correlation_id=cid, tenant_id=tenant_id)
    logger.info(f"Trip store worker persisting completed trip '{cid}'")
    await upsert_trip_result(
        tenant_id=tenant_id,
        user_id=user_id,
        correlation_id=cid,
        user_query=user_query,
        flight_results=flight_results,
        hotel_results=hotel_results,
        weather_results=weather_results,
        itinerary=itinerary,
        final_response=final_response,
        flight_degraded=flight_degraded,
        hotel_degraded=hotel_degraded,
        weather_degraded=weather_degraded,
    )
    await record_trip_event(
        tenant_id=tenant_id,
        correlation_id=cid,
        event_type="com.travelbrain.synthesis.completed.v1",
        payload=data,
    )
async def main():
    await event_bus.connect()
    loop = asyncio.get_running_loop()
    def handle_shutdown():
        logger.info("SIGTERM/SIGINT received. Initiating trip store worker drain...")
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
            handler=handle_synthesis_completed,
            stop_event=stop_event,
        )
    finally:
        await event_bus.close()
        logger.info("Trip store worker shutdown complete.")
if __name__ == "__main__":
    asyncio.run(main())