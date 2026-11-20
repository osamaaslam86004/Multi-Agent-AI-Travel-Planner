"""
Trip Store Worker: Subscribes to synthesis:completed streams and idempotently persists
trip results, append-only event audit logs, and LLM usage ledgers into Postgres DB.
"""

import asyncio
import logging
import os
import signal

try:
    import redis.asyncio as aioredis
except ImportError:
    aioredis = None

from services.common.db import (
    record_trip_event,
    upsert_trip_result,
)
from services.common.event_bus import EventBus
from services.common.schemas import CloudEvent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("travelbrain.trip_store")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
STREAM_IN = "stream:travel:synthesis:completed"
CONSUMER_GROUP = "cg-trip-store"
HOSTNAME = os.getenv("HOSTNAME") or os.getenv("POD_NAME") or "local-store-worker"
CONSUMER_NAME = f"trip-store-{HOSTNAME}-{os.getpid()}"

event_bus = EventBus(redis_url=REDIS_URL)
stop_event = asyncio.Event()


async def handle_synthesis_completed(event: CloudEvent) -> None:
    """Idempotently upserts completed trip into Postgres DB and records audit/usage."""
    data = event.data if isinstance(event.data, dict) else event.data.model_dump()

    cid = data.get("correlation_id")
    tenant_id = data.get("tenant_id", "default")
    user_id = data.get("user_id", "guest")
    query = data.get("user_query", "")

    if not cid:
        return

    logger.info(f"Trip-store persisting completed trip '{cid}' (tenant: {tenant_id})")

    await upsert_trip_result(
        tenant_id=tenant_id,
        user_id=user_id,
        correlation_id=cid,
        user_query=query,
        flight_results=data.get("flight_results", ""),
        hotel_results=data.get("hotel_results", ""),
        weather_results=data.get("weather_results", ""),
        itinerary=data.get("itinerary", ""),
        final_response=data.get("final_response", ""),
        flight_degraded=data.get("flight_degraded", False),
        hotel_degraded=data.get("hotel_degraded", False),
        weather_degraded=data.get("weather_degraded", False),
    )

    await record_trip_event(
        tenant_id=tenant_id,
        correlation_id=cid,
        event_type="com.travelbrain.trip.persisted.v1",
        payload=data,
    )


async def main():
    await event_bus.connect()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass

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


if __name__ == "__main__":
    asyncio.run(main())
