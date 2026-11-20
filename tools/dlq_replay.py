"""
DLQ Replay Tool: Admin CLI utility for inspecting and replaying failed messages
from the Dead Letter Queue ('stream:travel:dlq') back to their original target streams.
"""

import asyncio
import json
import logging
import os
import sys
from typing import Any

try:
    import redis.asyncio as aioredis
except ImportError:
    aioredis = None
from services.common.schemas import CloudEvent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dlq_replay")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
DLQ_STREAM = "stream:travel:dlq"


async def replay_dlq(max_messages: int = 100) -> int:
    """Replays messages from DLQ back to their original stream."""
    r = aioredis.from_url(
        REDIS_URL, password=REDIS_PASSWORD or None, decode_responses=True
    )
    try:
        await r.ping()
    except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
        logger.error(f"Failed to connect to Redis at {REDIS_URL}: {exc}")
        return 0

    messages = await r.xrange(DLQ_STREAM, count=max_messages)
    if not messages:
        logger.info("No messages found in DLQ.")
        await r.close()
        return 0

    logger.info(
        f"Found {len(messages)} messages in DLQ stream '{DLQ_STREAM}'. Starting replay..."
    )

    replayed_count = 0
    for msg_id, data in messages:
        orig_stream = data.get("original_stream")
        raw_event_data = data.get("data")

        if not orig_stream or not raw_event_data:
            logger.warning(f"Skipping malformed DLQ message {msg_id}")
            continue

        try:
            parsed_data = json.loads(raw_event_data)
            raw_event_str = parsed_data.get("event", "{}")
            parsed_event = (
                json.loads(raw_event_str)
                if isinstance(raw_event_str, str)
                else raw_event_str
            )

            ce = CloudEvent[Any](**parsed_event)
            payload = ce.model_dump()

            await r.xadd(
                orig_stream,
                {"event": json.dumps(payload)},
                maxlen=10000,
                approximate=True,
            )
            await r.xdel(DLQ_STREAM, msg_id)
            replayed_count += 1
            logger.info(
                f"Replayed message {msg_id} -> {orig_stream} (Event: {ce.type})"
            )

        except (
            OSError,
            RuntimeError,
            ValueError,
            json.JSONDecodeError,
            TypeError,
        ) as exc:
            logger.error(f"Failed replaying message {msg_id}: {exc}")

    await r.close()
    logger.info(f"DLQ Replay finish: {replayed_count} messages replayed.")
    return replayed_count


if __name__ == "__main__":
    count = 100
    if len(sys.argv) > 1:
        try:
            count = int(sys.argv[1])
        except ValueError:
            pass
    asyncio.run(replay_dlq(count))
