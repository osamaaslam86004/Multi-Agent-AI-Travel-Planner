"""
Scatter-Gather Barrier State Machine for Synthesis Service.
State Transitions: GATHERING -> SYNTHESIZING -> DONE.
Uses atomic Lua claims, deadline ZSET tracking, and Janitor-driven partial synthesis on expiration.
"""

import logging
import time
from typing import Any

try:
    import redis.asyncio as aioredis
except ImportError:
    aioredis = None

logger = logging.getLogger("travelbrain.barrier")

CLAIM_BARRIER_LUA = """
local barrier_key = KEYS[1]
local deadline_zset = KEYS[2]
local cid = ARGV[1]

local status = redis.call('HGET', barrier_key, 'status')
if status == 'SYNTHESIZING' or status == 'DONE' then
    return 0
end

local query = redis.call('HGET', barrier_key, 'user_query')
if not query or query == '' then
    return 0
end

local fl = redis.call('HEXISTS', barrier_key, 'flight_results')
local ht = redis.call('HEXISTS', barrier_key, 'hotel_results')
local wt = redis.call('HEXISTS', barrier_key, 'weather_results')

local force_partial = ARGV[2]

if (fl == 1 and ht == 1 and wt == 1) or force_partial == 'true' then
    redis.call('HSET', barrier_key, 'status', 'SYNTHESIZING')
    redis.call('HSET', barrier_key, 'synthesis_started_at', tostring(ARGV[3]))
    redis.call('ZREM', deadline_zset, cid)
    return 1
end

return 0
"""


class BarrierStateMachine:
    """
    Scatter-Gather state machine orchestrating multi-agent synchronization
    with deadline timeouts and partial degradation support.
    """

    def __init__(self, redis_client: Any, default_deadline_seconds: float = 15.0):
        self.redis = redis_client
        self.deadline_seconds = default_deadline_seconds
        self.deadline_zset = "barrier:deadlines"

    async def init_barrier(
        self,
        correlation_id: str,
        user_query: str,
        user_id: str = "guest",
        tenant_id: str = "default",
        deadline_seconds: float | None = None,
    ) -> None:
        """Initialize barrier hash and register deadline score in ZSET."""
        if not self.redis:
            return

        timeout = deadline_seconds or self.deadline_seconds
        deadline_ts = time.time() + timeout
        barrier_key = f"barrier:{correlation_id}"

        mapping = {
            "status": "GATHERING",
            "user_query": user_query,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "created_at": str(time.time()),
            "deadline_ts": str(deadline_ts),
        }
        await self.redis.hset(barrier_key, mapping=mapping)
        await self.redis.expire(barrier_key, 3600)

        # Register in deadline ZSET
        await self.redis.zadd(self.deadline_zset, {correlation_id: deadline_ts})

    async def record_agent_result(
        self,
        correlation_id: str,
        domain: str,  # 'flight', 'hotel', 'weather'
        results: str,
        source: str = "unknown",
        degraded: bool = False,
    ) -> None:
        """Records agent output into barrier hash."""
        if not self.redis:
            return

        barrier_key = f"barrier:{correlation_id}"
        mapping = {
            f"{domain}_results": results,
            f"{domain}_source": source,
            f"{domain}_degraded": str(degraded).lower(),
        }
        await self.redis.hset(barrier_key, mapping=mapping)
        await self.redis.expire(barrier_key, 3600)

    async def try_claim_synthesis(
        self, correlation_id: str, force_partial: bool = False
    ) -> bool:
        """
        Atomically transition state from GATHERING -> SYNTHESIZING via Lua script.
        Returns True if claim succeeded.
        """
        if not self.redis:
            return True

        barrier_key = f"barrier:{correlation_id}"
        now_str = str(time.time())
        force_str = "true" if force_partial else "false"

        res = await self.redis.eval(
            CLAIM_BARRIER_LUA,
            2,
            barrier_key,
            self.deadline_zset,
            correlation_id,
            force_str,
            now_str,
        )
        return res == 1

    async def get_barrier_data(self, correlation_id: str) -> dict[str, str]:
        """Returns full barrier state data."""
        if not self.redis:
            return {}
        barrier_key = f"barrier:{correlation_id}"
        return await self.redis.hgetall(barrier_key)

    async def check_expired_barriers(self) -> list[str]:
        """
        Janitor scan: finds barriers whose deadline_ts score <= current_time,
        marks missing agent domains as degraded, and returns list of correlation_ids ready for partial synthesis.
        """
        if not self.redis:
            return []

        now = time.time()
        expired_cids = await self.redis.zrangebyscore(
            self.deadline_zset, min=0, max=now
        )
        ready_for_synthesis: list[str] = []

        for cid in expired_cids:
            barrier_key = f"barrier:{cid}"
            data = await self.redis.hgetall(barrier_key)

            if not data or data.get("status") != "GATHERING":
                await self.redis.zrem(self.deadline_zset, cid)
                continue

            # Fill missing agent domains with degraded fallback markers
            updates = {}
            if "flight_results" not in data:
                updates["flight_results"] = (
                    "Flight data unavailable (deadline timeout)."
                )
                updates["flight_degraded"] = "true"
                updates["flight_source"] = "timeout_fallback"

            if "hotel_results" not in data:
                updates["hotel_results"] = "Hotel data unavailable (deadline timeout)."
                updates["hotel_degraded"] = "true"
                updates["hotel_source"] = "timeout_fallback"

            if "weather_results" not in data:
                updates["weather_results"] = (
                    "Weather data unavailable (deadline timeout)."
                )
                updates["weather_degraded"] = "true"
                updates["weather_source"] = "timeout_fallback"

            if updates:
                await self.redis.hset(barrier_key, mapping=updates)

            # Try claiming synthesis for partial generation
            claimed = await self.try_claim_synthesis(cid, force_partial=True)
            if claimed:
                logger.warning(
                    f"Janitor triggered partial synthesis for timed-out trip '{cid}'"
                )
                ready_for_synthesis.append(cid)

        return ready_for_synthesis

    async def mark_done(self, correlation_id: str) -> None:
        """Marks barrier status as DONE and cleans up deadline ZSET."""
        if not self.redis:
            return

        barrier_key = f"barrier:{correlation_id}"
        await self.redis.hset(barrier_key, "status", "DONE")
        await self.redis.zrem(self.deadline_zset, correlation_id)
