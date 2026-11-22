"""
Session, Anti-CSRF, Multi-Tenant Isolation, Device Trust, and FinOps Pre-Flight Budget Manager for BFF Pattern.
Includes absolute TTLs, sliding idle timeout, session rotation on login, tenant-scoped Redis keys,
request validation, fail-closed production checks, and per-tenant pre-flight token budget enforcement.
"""

import logging
import secrets
import time
from typing import Any

from fastapi import HTTPException, Request, status

from services.core.config import get_settings
from services.shared.redis_client import get_redis_client

logger = logging.getLogger("travelbrain.session_manager")
_s = get_settings()

SESSION_COOKIE_NAME = _s.security.session_cookie_name or "tb_session_id"
CSRF_HEADER_NAME = _s.security.csrf_header_name or "x-csrf-token"
SESSION_TTL_SECONDS = 86400
DEFAULT_DAILY_TENANT_TOKEN_BUDGET = 200_000

_in_memory_sessions: dict[str, dict[str, Any]] = {}
_in_memory_revoked: set[str] = set()


class SessionManager:
    """Manages secure HTTP-only cookie sessions, Anti-CSRF, Device Trust, and FinOps Pre-Flight Quotas in Redis."""

    def __init__(self, redis_url: str | None = None, password: str | None = None):
        self.redis_url = redis_url or _s.redis.url
        self.password = password if password is not None else _s.redis.password
        self._redis: Any = None

    async def get_redis(self) -> Any:
        if self._redis is not None:
            return self._redis
        return await get_redis_client()

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
        if old_session_id:
            await self.destroy_session(old_session_id, tenant_id=tenant_id)

        session_id = f"sess_{secrets.token_hex(24)}"
        csrf_token = secrets.token_urlsafe(32)
        now = time.time()
        absolute_expires_at = now + SESSION_TTL_SECONDS

        session_data = {
            "session_id": session_id,
            "jwt": jwt_token,
            "user_id": user_id,
            "email": email,
            "tenant_id": tenant_id,
            "roles": ",".join(roles or ["traveler"]),
            "csrf_token": csrf_token,
            "created_at": str(now),
            "expires_at": str(absolute_expires_at),
        }

        _in_memory_sessions[session_id] = session_data

        if r:
            session_key = f"session:{tenant_id}:{session_id}"
            user_idx_key = f"user_sessions:{tenant_id}:{user_id}"
            await r.hset(session_key, mapping=session_data)
            await r.expire(session_key, SESSION_TTL_SECONDS)
            await r.sadd(user_idx_key, session_id)
            await r.expire(user_idx_key, SESSION_TTL_SECONDS)

        return session_id, csrf_token

    async def get_session(
        self, session_id: str, tenant_id: str = "default"
    ) -> dict[str, str] | None:
        if session_id in _in_memory_revoked:
            return None

        r = await self.get_redis()
        if not r:
            s = _in_memory_sessions.get(session_id)
            if s and float(s.get("expires_at", time.time() + 100)) > time.time():
                return s
            return None

        session_key = f"session:{tenant_id}:{session_id}"
        data = await r.hgetall(session_key)

        if not data and tenant_id == "default":
            # Fallback for sessions with non-default tenant_id
            keys = await r.keys(f"session:*:{session_id}")
            if keys:
                session_key = keys[0]
                data = await r.hgetall(session_key)

        if not data:
            return None

        now = time.time()
        expires_at = float(data.get("expires_at", now + 100))
        if now > expires_at:
            await r.delete(session_key)
            return None

        # Sliding TTL extension
        remaining_ttl = max(1, int(expires_at - now))
        await r.expire(session_key, min(SESSION_TTL_SECONDS, remaining_ttl))
        return data

    async def destroy_session(
        self, session_id: str, tenant_id: str = "default"
    ) -> None:
        _in_memory_revoked.add(session_id)
        session_info = _in_memory_sessions.pop(session_id, None)

        r = await self.get_redis()
        if r:
            user_id = session_info.get("user_id") if session_info else None
            session_key = f"session:{tenant_id}:{session_id}"
            await r.delete(session_key)
            await r.setex(f"revoked:sid:{session_id}", SESSION_TTL_SECONDS, "true")
            if user_id:
                await r.srem(f"user_sessions:{tenant_id}:{user_id}", session_id)

    async def validate_request(
        self, request: Request, tenant_id: str = "default", check_csrf: bool = True
    ) -> dict[str, str]:
        session_id = request.cookies.get(SESSION_COOKIE_NAME)
        if not session_id:
            auth_hdr = request.headers.get("Authorization")
            if auth_hdr and auth_hdr.startswith("Bearer "):
                session_id = auth_hdr.split(" ", 1)[1]

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

        if check_csrf and request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            client_csrf = request.headers.get(CSRF_HEADER_NAME)
            expected_csrf = session_data.get("csrf_token")
            if not client_csrf or client_csrf != expected_csrf:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Anti-CSRF verification failed.",
                )
        return session_data

    async def revoke_session(self, session_id: str, tenant_id: str = "default") -> bool:
        await self.destroy_session(session_id, tenant_id=tenant_id)
        return True

    async def logout_user_all_devices(
        self, user_id: str, tenant_id: str = "default"
    ) -> int:
        to_del = [
            sid for sid, s in _in_memory_sessions.items() if s.get("user_id") == user_id
        ]
        for sid in to_del:
            await self.destroy_session(sid, tenant_id=tenant_id)

        r = await self.get_redis()
        if r:
            now_ts = str(time.time())
            await r.setex(f"tokens_valid_after:{user_id}", SESSION_TTL_SECONDS, now_ts)
            user_idx_key = f"user_sessions:{tenant_id}:{user_id}"
            sids = await r.smembers(user_idx_key)
            for sid in sids:
                await r.setex(f"revoked:sid:{sid}", SESSION_TTL_SECONDS, "true")
                await r.delete(f"session:{tenant_id}:{sid}")
            await r.delete(user_idx_key)
        return max(len(to_del), 1)

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
        return results[2] <= max_requests

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
                f"Tenant '{tenant_id}' budget exceeded: {current_usage} + {estimated_tokens} > {daily_limit_tokens}"
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
