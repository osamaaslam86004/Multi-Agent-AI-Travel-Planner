"""
Session, Anti-CSRF, and Multi-Tenant Isolation Management for BFF Pattern.
Includes absolute TTLs, session rotation on login, tenant-scoped Redis keys, and request validation.
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
SESSION_TTL_SECONDS = 86400  # 24 hours (Absolute & Sliding TTL)


class SessionManager:
    """Manages secure HTTP-only cookie sessions and Anti-CSRF protection in Redis with tenant isolation."""

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
        """
        Creates a new session in Redis, rotating out any previous session_id.
        Stores session data under tenant-scoped Redis key. Returns (session_id, csrf_token).
        """
        r = await self.get_redis()

        # Session Rotation: Destroy old session if present
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
        """Fetch session data from Redis, enforcing absolute TTL and sliding window."""
        r = await self.get_redis()
        if not r:
            return None

        # Primary lookup under tenant-scoped key
        session_key = f"session:{tenant_id}:{session_id}"
        data = await r.hgetall(session_key)

        # Fallback search if tenant_id was unspecified/unknown
        if not data and tenant_id == "default":
            keys = await r.keys(f"session:*:{session_id}")
            if keys:
                session_key = keys[0]
                data = await r.hgetall(session_key)

        if not data:
            return None

        now = time.time()
        expires_at = float(data.get("expires_at", now + 100))

        # Absolute TTL Enforcement
        if now > expires_at:
            logger.info(
                "Session %s reached absolute TTL expiry. Destroying.", session_id
            )
            await r.delete(session_key)
            return None

        # Refresh sliding TTL up to remaining absolute limit
        remaining_ttl = max(1, int(expires_at - now))
        await r.expire(session_key, min(SESSION_TTL_SECONDS, remaining_ttl))

        return data

    async def destroy_session(
        self, session_id: str, tenant_id: str = "default"
    ) -> None:
        """Log out / delete session."""
        r = await self.get_redis()
        if r:
            await r.delete(f"session:{tenant_id}:{session_id}")
            keys = await r.keys(f"session:*:{session_id}")
            for k in keys:
                await r.delete(k)

    async def validate_request(
        self, request: Request, tenant_id: str = "default"
    ) -> dict[str, str]:
        """
        Verifies session cookie and anti-CSRF token on mutating requests (POST/PUT/DELETE/PATCH).
        Returns validated session data dictionary.
        """
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

        # CSRF check for state-changing HTTP methods
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
        """Sliding-window rate limiter using Redis, tenant-scoped."""
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
