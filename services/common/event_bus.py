"""
Asynchronous Event Bus using Redis Streams and PubSub for CloudEvents choreography.
Includes PEL recovery via XAUTOCLAIM, max-retry Dead Letter Queue (DLQ), stream trimming,
and resilient consumer group initialization.
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
DLQ_STREAM = "stream:travel:dlq"


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

    async def publish(
        self, stream_name: str, event: CloudEvent[Any], maxlen: int = 10000
    ) -> str:
        """Publishes a CloudEvent to a Redis Stream with MAXLEN trimming."""
        if not self.client:
            await self.connect()
        payload = event.model_dump()
        message_id = await self.client.xadd(
            stream_name,
            {"event": json.dumps(payload)},
            maxlen=maxlen,
            approximate=True,
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

    async def create_consumer_group(
        self, stream_name: str, group_name: str, start_id: str = "$"
    ) -> None:
        """Idempotently create consumer group on stream using start_id ('$' default to avoid replay)."""
        if not self.client:
            await self.connect()
        try:
            await self.client.xgroup_create(
                stream_name, group_name, id=start_id, mkstream=True
            )
            logger.info(
                f"Created consumer group '{group_name}' on stream '{stream_name}' with start_id='{start_id}'"
            )
        except aioredis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    async def _process_single_message(
        self,
        stream_name: str,
        group_name: str,
        consumer_name: str,
        message_id: str,
        data: dict[str, Any],
        handler: Callable[[CloudEvent[Any]], Coroutine[Any, Any, None]],
        max_retries: int = 3,
    ) -> None:
        """Process message with delivery counter, idempotency, DLQ routing, and ACK."""
        try:
            # Check delivery attempt count from pending entries list
            pending_info = await self.client.xpending_range(
                stream_name, group_name, min=message_id, max=message_id, count=1
            )
            delivery_count = 1
            if pending_info and len(pending_info) > 0:
                delivery_count = pending_info[0].get("times_delivered", 1)

            if delivery_count > max_retries:
                logger.error(
                    f"Message {message_id} on stream '{stream_name}' exceeded max retries ({delivery_count} > {max_retries}). "
                    f"Routing to DLQ '{DLQ_STREAM}'."
                )
                await self.client.xadd(
                    DLQ_STREAM,
                    {
                        "original_stream": stream_name,
                        "group": group_name,
                        "consumer": consumer_name,
                        "message_id": message_id,
                        "data": json.dumps(data),
                        "delivery_count": str(delivery_count),
                    },
                    maxlen=10000,
                    approximate=True,
                )
                await self.client.xack(stream_name, group_name, message_id)
                return

            raw_event_str = data.get("event", "{}")
            raw_event = (
                json.loads(raw_event_str)
                if isinstance(raw_event_str, str)
                else raw_event_str
            )
            cloud_event = CloudEvent[Any](**raw_event)
            await handler(cloud_event)
            await self.client.xack(stream_name, group_name, message_id)
        except Exception:
            logger.exception(
                f"Failed processing message {message_id} on stream '{stream_name}' by '{consumer_name}'"
            )

    async def consume(
        self,
        stream_name: str,
        group_name: str,
        consumer_name: str,
        handler: Callable[[CloudEvent[Any]], Coroutine[Any, Any, None]],
        batch_size: int = 1,
        block_ms: int = 2000,
        min_idle_ms: int = 60000,
        stop_event: asyncio.Event | None = None,
    ) -> None:
        """
        Runs continuous loop:
        1. Autoclaim unacknowledged pending messages older than min_idle_ms via XAUTOCLAIM (PEL recovery).
        2. Read new messages via XREADGROUP ('>').
        3. Deliver to handler, track retries, route poison messages to DLQ, and ACK cleanly.
        """
        await self.create_consumer_group(stream_name, group_name, start_id="$")
        logger.info(
            f"Consumer '{consumer_name}' listening on stream '{stream_name}' (group: {group_name})"
        )
        while stop_event is None or not stop_event.is_set():
            try:
                # Step 1: Recover stuck PEL entries via XAUTOCLAIM
                try:
                    autoclaim_res = await self.client.xautoclaim(
                        stream_name,
                        group_name,
                        consumer_name,
                        min_idle_time=min_idle_ms,
                        start_id="0-0",
                        count=batch_size,
                    )
                    if autoclaim_res and len(autoclaim_res) >= 2:
                        claimed_messages = autoclaim_res[1]
                        for msg_id, msg_data in claimed_messages:
                            await self._process_single_message(
                                stream_name,
                                group_name,
                                consumer_name,
                                msg_id,
                                msg_data,
                                handler,
                            )
                except (aioredis.RedisError, TimeoutError, OSError) as pel_err:
                    logger.debug(f"XAUTOCLAIM info on '{stream_name}': {pel_err}")

                # Step 2: Read new messages
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
                        await self._process_single_message(
                            stream_name,
                            group_name,
                            consumer_name,
                            message_id,
                            data,
                            handler,
                        )
            except asyncio.CancelledError:
                break
            except (
                aioredis.RedisError,
                TimeoutError,
                OSError,
                RuntimeError,
                ValueError,
            ) as loop_err:
                logger.error(f"Error in consumer loop for '{stream_name}': {loop_err}")
                await asyncio.sleep(1.0)
