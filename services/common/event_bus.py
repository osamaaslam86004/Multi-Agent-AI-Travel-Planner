import asyncio

"""
Production Redis Streams Event Bus supporting Consumer Groups, PubSub & CloudEvents.
"""
import json
import logging
from typing import Any

try:
    import redis.asyncio as aioredis
except ImportError:
    aioredis = None
from services.common.schemas import CloudEvent
from services.core.config import get_settings

logger = logging.getLogger("travelbrain.event_bus")
DLQ_STREAM = "stream:travel:dlq"


class EventBus:
    """Production Redis Streams Event Bus supporting Consumer Groups & CloudEvents."""

    def __init__(self, redis_url: str | None = None, password: str | None = None):
        settings = get_settings()
        self.redis_url = redis_url or settings.redis.url
        self.password = password if password is not None else settings.redis.password
        self.client: Any = None
        self._last_percentages: dict[str, int] = {}

    @property
    def is_connected(self) -> bool:
        """Step 1 (A-3): Read-only property returning connection readiness."""
        return self.client is not None

    async def connect(self) -> None:
        if aioredis is None:
            logger.warning("redis-py not installed; EventBus running in dummy mode.")
            return
        if not self.client:
            self.client = aioredis.from_url(
                self.redis_url,
                password=self.password or None,
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
        return message_id

    async def subscribe(self, channel_name: str) -> Any:
        """Step 1 (A-3): Subscribe to PubSub channel for real-time SSE streaming."""
        if not self.client:
            await self.connect()
        if not self.client:
            raise RuntimeError("Redis EventBus is disconnected.")
        pubsub = self.client.pubsub()
        await pubsub.subscribe(channel_name)
        return pubsub

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
        pubsub_channel = f"events:{cid}"
        await self.client.publish(pubsub_channel, msg_payload)
        return msg_id

    async def consume(
        self,
        stream_name: str,
        group_name: str,
        consumer_name: str,
        handler: Any,
        stop_event: Any = None,
    ) -> None:
        """Consume messages from Redis stream using Consumer Groups with XACK & DLQ support."""
        if not self.client:
            await self.connect()
        if not self.client:
            logger.warning("Redis client unavailable; consume loop exiting.")
            return
        try:
            await self.client.xgroup_create(
                stream_name, group_name, id="0", mkstream=True
            )
        except Exception:
            pass  # Group already exists
        logger.info(
            f"Consumer '{consumer_name}' started listening on '{stream_name}' (group: '{group_name}')"
        )
        while stop_event is None or not stop_event.is_set():
            try:
                entries = await self.client.xreadgroup(
                    groupname=group_name,
                    consumername=consumer_name,
                    streams={stream_name: ">"},
                    count=10,
                    block=2000,
                )
                if not entries:
                    continue
                for _, messages in entries:
                    for msg_id, fields in messages:
                        raw_event = fields.get("event") or fields.get("data")
                        try:
                            if raw_event:
                                event_dict = (
                                    json.loads(raw_event)
                                    if isinstance(raw_event, str)
                                    else raw_event
                                )
                                from services.common.schemas import CloudEvent

                                if (
                                    isinstance(event_dict, dict)
                                    and "specversion" in event_dict
                                ):
                                    ce = CloudEvent[Any](**event_dict)
                                else:
                                    ce = CloudEvent[Any](
                                        data=event_dict,
                                        source=stream_name,
                                        type="custom",
                                    )
                                await handler(ce)
                            await self.client.xack(stream_name, group_name, msg_id)
                        except Exception as exc:
                            logger.error(
                                f"Error handling message {msg_id} on {stream_name}: {exc}"
                            )
                            # Send to DLQ
                            await self.client.xadd(
                                DLQ_STREAM,
                                {
                                    "original_stream": stream_name,
                                    "msg_id": msg_id,
                                    "error": str(exc),
                                    "event": str(raw_event),
                                },
                            )
                            await self.client.xack(stream_name, group_name, msg_id)
            except Exception as exc:
                if stop_event and stop_event.is_set():
                    break
                logger.error(f"Error in EventBus.consume loop for {stream_name}: {exc}")
                await asyncio.sleep(1)
