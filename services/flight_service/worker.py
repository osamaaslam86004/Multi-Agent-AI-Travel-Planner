"""
Flight Agent background worker subscribing to Redis Streams.
"""

import asyncio
import logging
import os
import signal

from services.common.event_bus import EventBus
from services.common.schemas import (
    CloudEvent,
    FlightResultPayload,
    PlanningInitiatedPayload,
)
from services.flight_service.provider import FlightProvider

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("travelbrain.flight_worker")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
STREAM_IN = "stream:travel:planning:initiated"
STREAM_OUT = "stream:travel:flights:completed"
CONSUMER_GROUP = "cg-flight-service"
CONSUMER_NAME = f"flight-worker-{os.getpid()}"

event_bus = EventBus(redis_url=REDIS_URL)
provider = FlightProvider(redis_url=REDIS_URL)
stop_event = asyncio.Event()


async def handle_planning_initiated(
    event: CloudEvent[PlanningInitiatedPayload],
) -> None:
    data = event.data
    correlation_id = (
        data.get("correlation_id") if isinstance(data, dict) else data.correlation_id
    )
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

    # Publish progress update to user stream
    await event_bus.publish_progress(
        f"trip:stream:{correlation_id}",
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
            type="com.travelbrain.flights.completed",
            traceparent=event.traceparent,
            data=FlightResultPayload(
                correlation_id=correlation_id,
                success=True,
                results=provider_res.text,
                source=provider_res.source,
                degraded=provider_res.degraded,
                cached=False,
            ),
        )
        await event_bus.publish(STREAM_OUT, out_event)
        # Notify SSE stream
        await event_bus.publish_progress(
            f"trip:stream:{correlation_id}",
            {
                "stage": "flights_completed",
                "message": "Flight recommendations compiled successfully.",
                "percentage": 40,
                "degraded": provider_res.degraded,
            },
        )
        logger.info(f"Published flight results for trip {correlation_id}")
    except Exception as exc:
        logger.error(f"Flight search failed for trip {correlation_id}: {exc}")
        out_event = CloudEvent[FlightResultPayload](
            source="/services/flight-agent",
            type="com.travelbrain.flights.completed",
            traceparent=event.traceparent,
            data=FlightResultPayload(
                correlation_id=correlation_id,
                success=False,
                results="Flight information currently unavailable.",
                source="error",
                degraded=True,
                error=str(exc),
            ),
        )
        await event_bus.publish(STREAM_OUT, out_event)


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
            handler=handle_planning_initiated,
            stop_event=stop_event,
        )
    finally:
        await provider.close()


if __name__ == "__main__":
    asyncio.run(main())
