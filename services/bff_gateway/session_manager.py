"""
Session, Anti-CSRF, Multi-Tenant Isolation, Device Trust, and FinOps Pre-Flight Budget Manager for BFF Pattern.
Includes absolute TTLs, session rotation on login, tenant-scoped Redis keys, request validation,
in-memory fallback when Redis is offline, and per-tenant pre-flight token budget enforcement.
"""
import logging
import os
import secrets
import time
from typing import Any

try:
    import redis.asyncio as aioredis
except ImportError:
    aioredis = None
from fastapi import HTTPException, Request, status

logger = logging.getLogger("travelbrain.session_manager")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
SESSION_COOKIE_NAME = "tb_session_id"
CSRF_HEADER_NAME = "x-csrf-token"
SESSION_TTL_SECONDS = 86400
DEFAULT_DAILY_TENANT_TOKEN_BUDGET = 200_000
_in_memory_sessions: dict[str, dict[str, Any]] = {}
_in_memory_revoked: set[str] = set()
class SessionManager:
    """Manages secure HTTP-only cookie sessions, Anti-CSRF, Device Trust, and FinOps Pre-Flight Quotas in Redis/Memory."""
    def __init__(self, redis_url: str = REDIS_URL, password: str = REDIS_PASSWORD):
        self.redis_url = redis_url
        self.password = password or None
        self._redis: Any = None
    async def get_redis(self) -> Any:
        if aioredis is None:
            return None
        if self._redis is None:
            try:
                self._redis = aioredis.from_url(
                    self.redis_url,
                    password=self.password,
                    encoding="utf-8",
                    decode_responses=True,
                )
                await self._redis.ping()
            except Exception:
                self._redis = None
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
        refresh_token: str | None = None,
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
            "refresh_token": refresh_token or "",
            "user_id": user_id,
            "email": email,
            "tenant_id": tenant_id,
            "roles": ",".join(roles or ["traveler"]),
            "csrf_token": csrf_token,
            "created_at": str(now),
            "expires_at": str(absolute_expires_at),
        }
        if r is None and os.getenv("ENVIRONMENT", "development").lower() in (
            "production",
            "staging",
        ):
            raise HTTPException(
                status_code=503, detail="Distributed session storage unavailable."
            )
        _in_memory_sessions[session_id] = session_data
        if r:
            session_key = f"session:{tenant_id}:{session_id}"
            user_idx_key = f"user_sessions:{tenant_id}:{user_id}"
            await r.hset(session_key, mapping=session_data)
            await r.expire(session_key, SESSION_TTL_SECONDS)
            await r.sadd(user_idx_key, session_id)
        return session_id, csrf_token
    async def get_session(
        self, session_id: str, tenant_id: str = "default"
    ) -> dict[str, str] | None:
        if session_id in _in_memory_revoked:
            return None
        r = await self.get_redis()
        if not r:
            if os.getenv(
                "APP_ENV", os.getenv("ENVIRONMENT", "development")
            ).lower() in ("production", "staging"):
                raise HTTPException(
                    status_code=503, detail="Distributed session storage unavailable."
                )
            s = _in_memory_sessions.get(session_id)
            if s and float(s.get("expires_at", time.time() + 100)) > time.time():
                return s
            return None
        session_key = f"session:{tenant_id}:{session_id}"
        data = await r.hgetall(session_key)
        if not data and tenant_id == "default":
            keys = [f"session:{tenant_id}:{session_id}"]
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
        return data
    async def destroy_session(
        self, session_id: str, tenant_id: str = "default"
    ) -> None:
        _in_memory_revoked.add(session_id)
        _in_memory_sessions.pop(session_id, None)
        r = await self.get_redis()
        if r:
            keys = [f"session:{tenant_id}:{session_id}"]
            for k in keys:
                data = await r.hgetall(k)
                uid = data.get("user_id")
                tenant = data.get("tenant_id", tenant_id)
                await r.delete(k)
                if uid:
                    await r.srem(f"user_sessions:{tenant}:{uid}", session_id)
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
        
        # Authoritative upstream revocation check (B-12)
        r = await self.get_redis()
        if r is not None:
            import hashlib
            sid_digest = hashlib.sha256(session_id.encode('utf-8')).hexdigest()
            if await r.get(f"revoked_sid:{sid_digest}"):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session has been revoked.")
            
            user_id = session_data["user_id"]
            tokens_valid_after = await r.get(f"user_tokens_valid_after:{user_id}")
            if tokens_valid_after:
                sess_created = float(session_data.get("created_at", 0))
                if sess_created < float(tokens_valid_after):
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session invalidated due to user logout-all.")
            
            u_status = await r.get(f"user_status:{user_id}")
            if u_status in ("suspended", "deactivated", "deleted"):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Account status is {u_status}. Access revoked.")
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
    async def list_user_sessions(
        self, user_id: str, tenant_id: str = "default", include_tokens: bool = False
    ) -> list[dict[str, Any]]:
        r = await self.get_redis()
        if not r:
            if os.getenv(
                "APP_ENV", os.getenv("ENVIRONMENT", "development")
            ).lower() in ("production", "staging"):
                raise HTTPException(
                    status_code=503, detail="Distributed session storage unavailable."
                )
            return [
                s for s in _in_memory_sessions.values() if s.get("user_id") == user_id
            ]
        sids = await r.smembers(f"user_sessions:{tenant_id}:{user_id}")
        output = []
        for sid in sids:
            data = await r.hgetall(f"session:{tenant_id}:{sid}")
            if data and data.get("user_id") == user_id:
                if not include_tokens:
                    data.pop("jwt", None)
                data.pop("csrf_token", None)
                output.append(data)
        return output
    async def logout_user_all_devices(
        self, user_id: str, tenant_id: str = "default"
    ) -> int:
        to_del = [
            sid for sid, s in _in_memory_sessions.items() if s.get("user_id") == user_id
        ]
        for sid in to_del:
            await self.destroy_session(sid, tenant_id=tenant_id)
        r = await self.get_redis()
        if r is None and os.getenv(
            "APP_ENV", os.getenv("ENVIRONMENT", "development")
        ).lower() in ("production", "staging"):
            raise HTTPException(
                status_code=503, detail="Distributed session storage unavailable."
            )
        count = len(to_del)
        if r:
            user_idx_key = f"user_sessions:{tenant_id}:{user_id}"
            sids = await r.smembers(user_idx_key)
            count = max(count, len(sids))
            for sid in sids:
                await r.delete(f"session:{tenant_id}:{sid}")
                _in_memory_sessions.pop(sid, None)
            await r.delete(user_idx_key)
        return count
    async def check_tenant_budget(
        self,
        tenant_id: str,
        estimated_tokens: int = 1000,
        daily_limit_tokens: int = 200000,
    ) -> tuple[bool, int]:
        r = await self.get_redis()
        if not r:
            if os.getenv("ENVIRONMENT", "development").lower() in (
                "production",
                "staging",
            ):
                raise HTTPException(
                    status_code=503, detail="Distributed rate/budget state unavailable."
                )
            return True, 0
        current_str = await r.get(f"tenant:budget:{tenant_id}")
        current = int(current_str) if current_str else 0
        if current + estimated_tokens > daily_limit_tokens:
            return False, current
        return True, current
    async def check_rate_limit(
        self,
        client_identifier: str,
        tenant_id: str = "default",
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> bool:
        r = await self.get_redis()
        if not r:
            if os.getenv("ENVIRONMENT", "development").lower() in (
                "production",
                "staging",
            ):
                raise HTTPException(
                    status_code=503, detail="Distributed rate-limit state unavailable."
                )
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