#!/usr/bin/env python3
"""
Production Security Tool: Rotate and Invalidate Legacy Refresh Tokens.
Invalidates all active refresh tokens prior to a specified timestamp.
"""
import asyncio
import logging
import time

from services.shared.redis_client import get_redis_client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tools.rotate_refresh_tokens")
async def rotate_refresh_tokens():
    r = await get_redis_client()
    if r is None:
        logger.error("Redis client unavailable for token rotation.")
        return
    now_ts = time.time()
    logger.info("Setting global tokens_valid_after timestamp to current time...")
    await r.set("global_tokens_valid_after", str(now_ts))
    logger.info("Legacy refresh token rotation completed successfully.")
if __name__ == "__main__":
    asyncio.run(rotate_refresh_tokens())