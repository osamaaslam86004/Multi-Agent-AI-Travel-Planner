"""
Asynchronous Event Bus using Redis Streams and PubSub for CloudEvents choreography.
Includes PEL recovery via XAUTOCLAIM, max-retry Dead Letter Queue (DLQ), stream trimming (MAXLEN ~ 10000),
per-trip event streams (trip:events:{id}) with TTLs, and resilient consumer group initialization.
"""

import asyncio
import json
import logging
from collections.abc import Callable, Coroutine
from typing import Any

import redis.asyncio as aioredis
from redis.exceptions import ResponseError

from services.common.schemas import CloudEvent

logger = logging.getLogger("travelbrain.event_bus")
from services.core.config import get_settings

# Centralized settings fallback
# REDIS_PASSWORD initialized via get_settings()
DLQ_STREAM = "stream:travel:dlq"


class EventBus:
    """Production Redis Streams Event Bus supporting Consumer Groups & CloudEvents."""

    def __init__(self, redis_url: str | None = None, password: str | None = None):
        settings = get_settings()
        self.redis_url = redis_url or settings.redis.url
        self.password = password if password is not None else settings.redis.password
        self.redis_url = redis_url
        self.password = password or None
        self.client: Any = None
        self._last_percentages: dict[str, int] = {}

    async def connect(self) -> None:
        if aioredis is None:
            logger.warning("redis-py not installed; EventBus running in dummy mode.")
            return
        if not self.client:
            self.client = aioredis.from_url(
                self.redis_url,
                password=self.password,
                encoding="utf-8",
                decode_responses=True,
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
        if not self.client:
            await self.connect()
        if not self.client:
            return "dummy-msg-id"
        if not event.subject and isinstance(event.data, dict):
            event.subject = event.data.get("correlation_id")
        elif not event.subject and hasattr(event.data, "correlation_id"):
            event.subject = event.data.correlation_id
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

    async def publish_progress(
        self, correlation_id: str, update: dict[str, Any]
    ) -> str:
        if not self.client:
            await self.connect()
        if not self.client:
            return "0-0"
        cid = correlation_id.replace("trip:stream:", "").replace("trip:events:", "")
        stream_name = f"trip:events:{cid}"
        raw_pct = update.get("percentage", 0)
        last_pct = self._last_percentages.get(cid, 0)
        mono_pct = max(last_pct, raw_pct)
        self._last_percentages[cid] = mono_pct
        update["percentage"] = mono_pct
        update["correlation_id"] = cid
        msg_payload = json.dumps(update)
        msg_id = await self.client.xadd(
            stream_name,
            {"data": msg_payload},
            maxlen=1000,
            approximate=True,
        )
        await self.client.expire(stream_name, 86400)
        pubsub_channel = f"trip:stream:{cid}"
        await self.client.publish(pubsub_channel, msg_payload)
        return msg_id

    async def create_consumer_group(
        self, stream_name: str, group_name: str, start_id: str = "$"
    ) -> None:
        if not self.client:
            await self.connect()
        if not self.client:
            return
        try:
            await self.client.xgroup_create(
                stream_name, group_name, id=start_id, mkstream=True
            )
            logger.info(
                f"Created consumer group '{group_name}' on stream '{stream_name}' with start_id='{start_id}'"
            )
        except ResponseError as e:
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
        try:
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
        await self.create_consumer_group(stream_name, group_name, start_id="$")
        logger.info(
            f"Consumer '{consumer_name}' listening on stream '{stream_name}' (group: {group_name})"
        )
        while stop_event is None or not stop_event.is_set():
            try:
                if not self.client:
                    await asyncio.sleep(1.0)
                    continue
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
                except (
                    ResponseError,
                    aioredis.RedisError,
                    OSError,
                    RuntimeError,
                    TimeoutError,
                    ValueError,
                ) as pel_err:
                    logger.debug(f"XAUTOCLAIM info on '{stream_name}': {pel_err}")
                try:
                    entries = await self.client.xreadgroup(
                        group_name,
                        consumer_name,
                        {stream_name: ">"},
                        count=batch_size,
                        block=block_ms,
                    )
                except ResponseError as re_err:
                    if "NOGROUP" in str(re_err):
                        logger.warning(
                            f"NOGROUP error detected on '{stream_name}'. Re-creating consumer group '{group_name}' after Redis eviction..."
                        )
                        await self.create_consumer_group(
                            stream_name, group_name, start_id="$"
                        )
                        await asyncio.sleep(0.5)
                        continue
                    raise
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
                ResponseError,
                aioredis.RedisError,
                OSError,
                RuntimeError,
                TimeoutError,
                ValueError,
                json.JSONDecodeError,
            ) as loop_err:
                logger.error(f"Error in consumer loop for '{stream_name}': {loop_err}")
                await asyncio.sleep(1.0)
