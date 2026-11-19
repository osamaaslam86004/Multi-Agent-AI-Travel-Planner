"""
Synthesis & Itinerary Worker: Scatter-Gather Barrier Aggregator and LLM Orchestrator.
"""

import asyncio
import logging
import os
import signal

from services.common.event_bus import EventBus
from services.common.schemas import (
    CloudEvent,
    SynthesisCompletedPayload,
)
from services.synthesis_service.synthesizer import SynthesisEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("travelbrain.synthesis_worker")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
STREAM_FLIGHTS = "stream:travel:flights:completed"
STREAM_HOTELS = "stream:travel:hotels:completed"
STREAM_WEATHER = "stream:travel:weather:completed"
STREAM_OUT = "stream:travel:synthesis:completed"
CONSUMER_GROUP = "cg-synthesis-service"
CONSUMER_NAME = f"synthesis-worker-{os.getpid()}"

event_bus = EventBus(redis_url=REDIS_URL)
engine = SynthesisEngine()
stop_event = asyncio.Event()


async def check_and_synthesize(correlation_id: str, traceparent: str | None) -> None:
    """Checks if scatter-gather barrier is fulfilled, then synthesizes final itinerary."""
    r = event_bus.client
    barrier_key = f"barrier:{correlation_id}"
    is_synthesizing = await r.hget(barrier_key, "synthesis_started")
    if is_synthesizing == "true":
        return

    data = await r.hgetall(barrier_key)
    has_flights = "flight_results" in data
    has_hotels = "hotel_results" in data
    has_weather = "weather_results" in data

    if has_flights and has_hotels and has_weather:
        await r.hset(barrier_key, "synthesis_started", "true")
        logger.info(
            f"Barrier complete for trip {correlation_id}. Triggering synthesis LLM..."
        )
        await event_bus.publish_progress(
            f"trip:stream:{correlation_id}",
            {
                "stage": "synthesis_in_progress",
                "message": "Synthesizing multi-agent intelligence into day-by-day itinerary...",
                "percentage": 75,
            },
        )
        query = data.get("user_query", "Travel Plan")
        user_id = data.get("user_id", "guest")
        flights = data.get("flight_results", "")
        hotels = data.get("hotel_results", "")
        weather = data.get("weather_results", "")

        flight_degraded = data.get("flight_degraded", "false").lower() == "true"
        hotel_degraded = data.get("hotel_degraded", "false").lower() == "true"
        weather_degraded = data.get("weather_degraded", "false").lower() == "true"

        itinerary = await engine.generate_itinerary(query, flights, hotels, weather)
        final_response = await engine.format_final_response(
            query, flights, hotels, weather, itinerary
        )

        out_event = CloudEvent[SynthesisCompletedPayload](
            source="/services/synthesis-service",
            type="com.travelbrain.synthesis.completed",
            traceparent=traceparent,
            data=SynthesisCompletedPayload(
                correlation_id=correlation_id,
                user_id=user_id,
                user_query=query,
                flight_results=flights,
                hotel_results=hotels,
                weather_results=weather,
                itinerary=itinerary,
                final_response=final_response,
                flight_degraded=flight_degraded,
                hotel_degraded=hotel_degraded,
                weather_degraded=weather_degraded,
            ),
        )
        await event_bus.publish(STREAM_OUT, out_event)

        await event_bus.publish_progress(
            f"trip:stream:{correlation_id}",
            {
                "stage": "completed",
                "message": "Trip plan complete!",
                "percentage": 100,
                "final_response": final_response,
                "itinerary": itinerary,
                "degraded": flight_degraded or hotel_degraded or weather_degraded,
            },
        )
        logger.info(
            f"Synthesis finished and delivered to client for trip {correlation_id}"
        )


async def handle_flight_completed(event: CloudEvent) -> None:
    data = event.data if isinstance(event.data, dict) else event.data.model_dump()
    cid = data["correlation_id"]
    r = event_bus.client
    mapping = {
        "flight_results": data.get("results", ""),
        "flight_degraded": str(data.get("degraded", False)),
        "flight_source": data.get("source", "unknown"),
    }
    await r.hset(f"barrier:{cid}", mapping=mapping)
    await r.expire(f"barrier:{cid}", 3600)
    await check_and_synthesize(cid, event.traceparent)


async def handle_hotel_completed(event: CloudEvent) -> None:
    data = event.data if isinstance(event.data, dict) else event.data.model_dump()
    cid = data["correlation_id"]
    r = event_bus.client
    mapping = {
        "hotel_results": data.get("results", ""),
        "hotel_degraded": str(data.get("degraded", False)),
        "hotel_source": data.get("source", "unknown"),
    }
    await r.hset(f"barrier:{cid}", mapping=mapping)
    await r.expire(f"barrier:{cid}", 3600)
    await check_and_synthesize(cid, event.traceparent)


async def handle_weather_completed(event: CloudEvent) -> None:
    data = event.data if isinstance(event.data, dict) else event.data.model_dump()
    cid = data["correlation_id"]
    r = event_bus.client
    mapping = {
        "weather_results": data.get("results", ""),
        "weather_degraded": str(data.get("degraded", False)),
        "weather_source": data.get("source", "unknown"),
    }
    await r.hset(f"barrier:{cid}", mapping=mapping)
    await r.expire(f"barrier:{cid}", 3600)
    await check_and_synthesize(cid, event.traceparent)


async def handle_planning_initiated(event: CloudEvent) -> None:
    data = event.data if isinstance(event.data, dict) else event.data.model_dump()
    cid = data["correlation_id"]
    r = event_bus.client
    await r.hset(
        f"barrier:{cid}",
        mapping={
            "user_query": data.get("user_query", ""),
            "user_id": data.get("user_id", "guest"),
            "destination": data.get("destination", "") or "",
            "departure_city": data.get("departure_city", "") or "",
        },
    )
    await r.expire(f"barrier:{cid}", 3600)


async def main():
    await event_bus.connect()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass
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
            handle_flight_completed,
            stop_event=stop_event,
        ),
        event_bus.consume(
            STREAM_HOTELS,
            CONSUMER_GROUP,
            f"{CONSUMER_NAME}-ht",
            handle_hotel_completed,
            stop_event=stop_event,
        ),
        event_bus.consume(
            STREAM_WEATHER,
            CONSUMER_GROUP,
            f"{CONSUMER_NAME}-wt",
            handle_weather_completed,
            stop_event=stop_event,
        ),
    )


if __name__ == "__main__":
    asyncio.run(main())
