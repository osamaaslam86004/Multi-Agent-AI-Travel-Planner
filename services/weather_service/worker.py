"""
Weather Agent background worker subscribing to Redis Streams.
"""

import asyncio
import logging
import os
import signal

import redis.asyncio as aioredis

from services.common.event_bus import EventBus
from services.common.schemas import (
    CloudEvent,
    PlanningInitiatedPayload,
    WeatherResultPayload,
)
from services.weather_service.provider import WeatherProvider

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("travelbrain.weather_worker")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
STREAM_IN = "stream:travel:planning:initiated"
STREAM_OUT = "stream:travel:weather:completed"
CONSUMER_GROUP = "cg-weather-service"
HOSTNAME = os.getenv("HOSTNAME") or os.getenv("POD_NAME") or "local-worker"
CONSUMER_NAME = f"weather-worker-{HOSTNAME}-{os.getpid()}"
event_bus = EventBus(redis_url=REDIS_URL)
provider = WeatherProvider(redis_url=REDIS_URL)
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
    dates = (
        data.get("dates") if isinstance(data, dict) else getattr(data, "dates", None)
    )
    logger.info(
        f"Processing weather forecast for trip {correlation_id} (query: '{query}', dest: '{destination}')"
    )
    # Publish progress update to user stream
    await event_bus.publish_progress(
        f"trip:stream:{correlation_id}",
        {
            "stage": "weather_in_progress",
            "message": "Weather Agent is gathering forecast and climatological conditions...",
            "percentage": 35,
        },
    )
    try:
        provider_res = await provider.get_weather(
            query=query,
            destination=destination,
            dates=dates,
        )
        out_event = CloudEvent[WeatherResultPayload](
            source="/services/weather-agent",
            type="com.travelbrain.weather.completed",
            traceparent=event.traceparent,
            data=WeatherResultPayload(
                correlation_id=correlation_id,
                success=True,
                results=provider_res.text,
                source=provider_res.source,
                degraded=provider_res.degraded,
                cached=False,
            ),
        )
        await event_bus.publish(STREAM_OUT, out_event)
        await event_bus.publish_progress(
            f"trip:stream:{correlation_id}",
            {
                "stage": "weather_completed",
                "message": "Weather forecast compiled successfully.",
                "percentage": 60,
                "degraded": provider_res.degraded,
            },
        )
        logger.info(f"Published weather results for trip {correlation_id}")
    except (
        aioredis.RedisError,
        TimeoutError,
        OSError,
        RuntimeError,
        ValueError,
    ) as exc:
        logger.error(f"Weather query failed for trip {correlation_id}: {exc}")
        out_event = CloudEvent[WeatherResultPayload](
            source="/services/weather-agent",
            type="com.travelbrain.weather.completed",
            traceparent=event.traceparent,
            data=WeatherResultPayload(
                correlation_id=correlation_id,
                success=False,
                results="Weather information currently unavailable.",
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
