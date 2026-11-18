"""
Session and CSRF management for the Backend-For-Frontend (BFF) Pattern.
"""

import os
import secrets
import time
from typing import Any

import redis.asyncio as aioredis
from fastapi import HTTPException, Request, status

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
SESSION_COOKIE_NAME = "tb_session_id"
CSRF_HEADER_NAME = "x-csrf-token"
SESSION_TTL_SECONDS = 86400  # 24 hours


class SessionManager:
    """Manages secure HTTP-only cookie sessions and Anti-CSRF protection in Redis."""

    def __init__(self, redis_url: str = REDIS_URL):
        self.redis_url = redis_url
        self._redis: aioredis.Redis | None = None

    async def get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(
                self.redis_url, encoding="utf-8", decode_responses=True
            )
        return self._redis

    async def create_session(
        self,
        jwt_token: str,
        user_id: str,
        email: str,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[str, str]:
        """
        Creates a new session in Redis, returning (session_id, csrf_token).
        The raw JWT is saved in Redis and never exposed directly to localStorage.
        """
        r = await self.get_redis()
        session_id = f"sess_{secrets.token_hex(24)}"
        csrf_token = secrets.token_urlsafe(32)

        session_key = f"session:{session_id}"
        session_data = {
            "jwt": jwt_token,
            "user_id": user_id,
            "email": email,
            "csrf_token": csrf_token,
            "created_at": str(time.time()),
        }
        await r.hset(session_key, mapping=session_data)
        await r.expire(session_key, SESSION_TTL_SECONDS)
        return session_id, csrf_token

    async def get_session(self, session_id: str) -> dict[str, str] | None:
        """Fetch session data from Redis."""
        r = await self.get_redis()
        session_key = f"session:{session_id}"
        data = await r.hgetall(session_key)
        if not data:
            return None
        # Refresh session TTL on active use (sliding window)
        await r.expire(session_key, SESSION_TTL_SECONDS)
        return data

    async def destroy_session(self, session_id: str) -> None:
        """Log out / delete session."""
        r = await self.get_redis()
        await r.delete(f"session:{session_id}")

    async def validate_request(self, request: Request) -> dict[str, str]:
        """
        Verifies session cookie and anti-CSRF token on mutating requests (POST/PUT/DELETE).
        Returns session dictionary with JWT.
        """
        session_id = request.cookies.get(SESSION_COOKIE_NAME)
        if not session_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required. Missing session cookie.",
            )

        session_data = await self.get_session(session_id)
        if not session_data or "jwt" not in session_data:
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
        self, client_identifier: str, max_requests: int = 60, window_seconds: int = 60
    ) -> bool:
        """Sliding-window rate limiter using Redis."""
        r = await self.get_redis()
        now = time.time()
        key = f"ratelimit:{client_identifier}"
        pipeline = r.pipeline()
        pipeline.zremrangebyscore(key, 0, now - window_seconds)
        pipeline.zadd(key, {f"{now}-{secrets.token_hex(4)}": now})
        pipeline.zcard(key)
        pipeline.expire(key, window_seconds)
        results = await pipeline.execute()
        current_count = results[2]
        return current_count <= max_requests
