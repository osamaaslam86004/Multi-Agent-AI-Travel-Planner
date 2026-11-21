"""
Session, Anti-CSRF, Multi-Tenant Isolation, and FinOps Pre-Flight Budget Manager for BFF Pattern.
Includes absolute TTLs, session rotation on login, tenant-scoped Redis keys, request validation,
and per-tenant pre-flight token budget enforcement.
"""

import logging
import os
import secrets
import time
from typing import Any

import redis.asyncio as aioredis
from fastapi import HTTPException, Request, status

logger = logging.getLogger("travelbrain.session_manager")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
SESSION_COOKIE_NAME = "tb_session_id"
CSRF_HEADER_NAME = "x-csrf-token"
SESSION_TTL_SECONDS = 86400
DEFAULT_DAILY_TENANT_TOKEN_BUDGET = 200_000


class SessionManager:
    """Manages secure HTTP-only cookie sessions, Anti-CSRF, and FinOps Pre-Flight Quotas in Redis."""

    def __init__(self, redis_url: str = REDIS_URL, password: str = REDIS_PASSWORD):
        self.redis_url = redis_url
        self.password = password or None
        self._redis: Any = None

    async def get_redis(self) -> Any:
        if aioredis is None:
            return None
        if self._redis is None:
            self._redis = aioredis.from_url(
                self.redis_url,
                password=self.password,
                encoding="utf-8",
                decode_responses=True,
            )
        return self._redis

    async def create_session(
        self,
        jwt_token: str,
        user_id: str,
        email: str,
        tenant_id: str = "default",
        roles: list[str] | None = None,
        old_session_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[str, str]:
        r = await self.get_redis()
        if old_session_id and r:
            await self.destroy_session(old_session_id, tenant_id=tenant_id)
        session_id = f"sess_{secrets.token_hex(24)}"
        csrf_token = secrets.token_urlsafe(32)
        now = time.time()
        absolute_expires_at = now + SESSION_TTL_SECONDS
        session_key = f"session:{tenant_id}:{session_id}"
        session_data = {
            "jwt": jwt_token,
            "user_id": user_id,
            "email": email,
            "tenant_id": tenant_id,
            "roles": ",".join(roles or ["traveler"]),
            "csrf_token": csrf_token,
            "created_at": str(now),
            "expires_at": str(absolute_expires_at),
        }
        if r:
            await r.hset(session_key, mapping=session_data)
            await r.expire(session_key, SESSION_TTL_SECONDS)
        return session_id, csrf_token

    async def get_session(
        self, session_id: str, tenant_id: str = "default"
    ) -> dict[str, str] | None:
        r = await self.get_redis()
        if not r:
            return None
        session_key = f"session:{tenant_id}:{session_id}"
        data = await r.hgetall(session_key)
        if not data and tenant_id == "default":
            keys = await r.keys(f"session:*:{session_id}")
            if keys:
                session_key = keys[0]
                data = await r.hgetall(session_key)
        if not data:
            return None
        now = time.time()
        expires_at = float(data.get("expires_at", now + 100))
        if now > expires_at:
            logger.info(
                "Session %s reached absolute TTL expiry. Destroying.", session_id
            )
            await r.delete(session_key)
            return None
        remaining_ttl = max(1, int(expires_at - now))
        await r.expire(session_key, min(SESSION_TTL_SECONDS, remaining_ttl))
        return data

    async def destroy_session(
        self, session_id: str, tenant_id: str = "default"
    ) -> None:
        r = await self.get_redis()
        if r:
            await r.delete(f"session:{tenant_id}:{session_id}")
            keys = await r.keys(f"session:*:{session_id}")
            for k in keys:
                await r.delete(k)

    async def validate_request(
        self, request: Request, tenant_id: str = "default"
    ) -> dict[str, str]:
        session_id = request.cookies.get(SESSION_COOKIE_NAME)
        if not session_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required. Missing session cookie.",
            )
        session_data = await self.get_session(session_id, tenant_id=tenant_id)
        if not session_data or "user_id" not in session_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has expired or is invalid.",
            )
        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            client_csrf = request.headers.get(CSRF_HEADER_NAME)
            expected_csrf = session_data.get("csrf_token")
            if not client_csrf or client_csrf != expected_csrf:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Anti-CSRF verification failed.",
                )
        return session_data

    async def check_rate_limit(
        self,
        client_identifier: str,
        tenant_id: str = "default",
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> bool:
        r = await self.get_redis()
        if not r:
            return True
        now = time.time()
        key = f"ratelimit:{tenant_id}:{client_identifier}"
        pipeline = r.pipeline()
        pipeline.zremrangebyscore(key, 0, now - window_seconds)
        pipeline.zadd(key, {f"{now}-{secrets.token_hex(4)}": now})
        pipeline.zcard(key)
        pipeline.expire(key, window_seconds)
        results = await pipeline.execute()
        current_count = results[2]
        return current_count <= max_requests

    async def check_tenant_budget(
        self,
        tenant_id: str = "default",
        estimated_tokens: int = 5000,
        daily_limit_tokens: int = DEFAULT_DAILY_TENANT_TOKEN_BUDGET,
    ) -> tuple[bool, int]:
        r = await self.get_redis()
        if not r:
            return True, 0
        date_str = time.strftime("%Y-%m-%d")
        budget_key = f"tenant:budget:{tenant_id}:{date_str}"
        val = await r.get(budget_key)
        current_usage = int(val or 0)

        if current_usage + estimated_tokens > daily_limit_tokens:
            logger.warning(
                f"Tenant '{tenant_id}' pre-flight budget exceeded: {current_usage} + {estimated_tokens} > {daily_limit_tokens}"
            )
            return False, current_usage
        return True, current_usage

    async def increment_tenant_token_usage(
        self, tenant_id: str, tokens_used: int
    ) -> int:
        r = await self.get_redis()
        if not r:
            return tokens_used
        date_str = time.strftime("%Y-%m-%d")
        budget_key = f"tenant:budget:{tenant_id}:{date_str}"
        new_val = await r.incrby(budget_key, tokens_used)
        await r.expire(budget_key, 172800)
        return new_val
