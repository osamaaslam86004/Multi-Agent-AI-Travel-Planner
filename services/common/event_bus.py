"""
Asynchronous Event Bus using Redis Streams and PubSub for CloudEvents choreography.
"""

import asyncio
import json
import logging
import os
from collections.abc import Callable, Coroutine
from typing import Any

import redis.asyncio as aioredis

from services.common.schemas import CloudEvent

logger = logging.getLogger("travelbrain.event_bus")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")


class EventBus:
    """Production Redis Streams Event Bus supporting Consumer Groups & CloudEvents."""

    def __init__(self, redis_url: str = REDIS_URL):
        self.redis_url = redis_url
        self.client: aioredis.Redis | None = None

    async def connect(self) -> None:
        if not self.client:
            self.client = aioredis.from_url(
                self.redis_url, encoding="utf-8", decode_responses=True
            )
            await self.client.ping()
            logger.info(f"Connected to EventBus Redis at {self.redis_url}")

    async def close(self) -> None:
        if self.client:
            await self.client.aclose()
            self.client = None
            logger.info("Closed EventBus connection.")

    async def publish(self, stream_name: str, event: CloudEvent[Any]) -> str:
        """Publishes a CloudEvent to a Redis Stream."""
        if not self.client:
            await self.connect()

        payload = event.model_dump()
        # Redis Stream values must be dict of str -> str/bytes
        message_id = await self.client.xadd(
            stream_name,
            {"event": json.dumps(payload)},
        )
        logger.debug(
            f"Published event {event.id} ({event.type}) to stream '{stream_name}' id: {message_id}"
        )
        return message_id

    async def publish_progress(self, channel_name: str, update: dict[str, Any]) -> int:
        """Publishes real-time streaming progress to a Redis PubSub channel."""
        if not self.client:
            await self.connect()
        return await self.client.publish(channel_name, json.dumps(update))

    async def create_consumer_group(self, stream_name: str, group_name: str) -> None:
        """Idempotently create consumer group on stream."""
        if not self.client:
            await self.connect()
        try:
            await self.client.xgroup_create(
                stream_name, group_name, id="0", mkstream=True
            )
            logger.info(
                f"Created consumer group '{group_name}' on stream '{stream_name}'"
            )
        except aioredis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    async def consume(
        self,
        stream_name: str,
        group_name: str,
        consumer_name: str,
        handler: Callable[[CloudEvent[Any]], Coroutine[Any, Any, None]],
        batch_size: int = 1,
        block_ms: int = 2000,
        stop_event: asyncio.Event | None = None,
    ) -> None:
        """
        Runs continuous loop reading from stream consumer group, executing handler, and acking.
        """
        await self.create_consumer_group(stream_name, group_name)
        logger.info(
            f"Consumer '{consumer_name}' started listening on stream '{stream_name}' (group: {group_name})"
        )

        while stop_event is None or not stop_event.is_set():
            try:
                # Read new messages
                entries = await self.client.xreadgroup(
                    group_name,
                    consumer_name,
                    {stream_name: ">"},
                    count=batch_size,
                    block=block_ms,
                )

                if not entries:
                    await asyncio.sleep(0.01)
                    continue

                for _, messages in entries:
                    for message_id, data in messages:
                        try:
                            raw_event = json.loads(data["event"])
                            cloud_event = CloudEvent[Any](**raw_event)
                            await handler(cloud_event)
                            # Acknowledge successful processing
                            await self.client.xack(stream_name, group_name, message_id)
                        except Exception as exc:
                            logger.error(
                                f"Failed processing message {message_id} on stream {stream_name}: {exc}",
                                exc_info=True,
                            )
                            # Can optionally route to DLQ here
            except asyncio.CancelledError:
                break
            except Exception as loop_err:
                logger.error(f"Error in consumer loop: {loop_err}")
                await asyncio.sleep(1.0)
