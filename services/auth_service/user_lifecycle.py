"""
User Account Lifecycle Management Service.
Handles persistent user profiles, account state transitions, identity provider linking,
login history tracking, active sessions, and multi-device revocation.
"""

import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import HTTPException, status

from services.auth_service.models import (
    AccountStatus,
    ActiveSessionResponse,
    LinkedProviderInfo,
    LoginHistoryEntry,
    UserProfile,
)
from services.auth_service.security import generate_user_id
from services.shared.redis_client import get_redis_client

logger = logging.getLogger("travelbrain.auth.user_lifecycle")

# Fallback store when Postgres/Redis are unavailable in local dev
_in_memory_profiles: dict[str, UserProfile] = {}
_in_memory_login_history: dict[str, list[LoginHistoryEntry]] = {}
_in_memory_sessions: dict[str, list[dict[str, Any]]] = {}


def assert_login_allowed(profile: UserProfile) -> None:
    """Step 6 (H-3): Centralized account status check for all login paths."""
    if profile.status != AccountStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account status is '{profile.status.value}'. Login disallowed.",
        )


class UserLifecycleService:
    """Core User Profile and Account Lifecycle Service."""

    def __init__(self, redis_client: Any = None):
        self.redis = redis_client

    async def _get_r(self) -> Any:
        if self.redis is not None:
            return self.redis
        return await get_redis_client()

    async def get_or_create_profile(
        self,
        email: str,
        tenant_id: str = "default",
        auth_provider: str = "direct",
        display_name: str | None = None,
        email_verified: bool = False,
    ) -> UserProfile:
        email_clean = email.lower().strip()
        user_id = generate_user_id(email_clean)
        now_str = datetime.now(UTC).isoformat()

        if user_id in _in_memory_profiles:
            profile = _in_memory_profiles[user_id]
            if email_verified and not profile.email_verified:
                profile.email_verified = True
                profile.updated_at = now_str
            return profile

        profile = UserProfile(
            user_id=user_id,
            email=email_clean,
            display_name=display_name or email_clean.split("@")[0].title(),
            tenant_id=tenant_id,
            status=AccountStatus.ACTIVE,
            email_verified=email_verified or (auth_provider != "direct"),
            created_at=now_str,
            updated_at=now_str,
        )
        if auth_provider != "direct":
            profile.linked_providers.append(
                LinkedProviderInfo(
                    provider=auth_provider,
                    provider_user_id=user_id,
                    email=email_clean,
                    linked_at=now_str,
                )
            )
        _in_memory_profiles[user_id] = profile
        return profile

    async def get_profile(self, user_id: str) -> UserProfile | None:
        return _in_memory_profiles.get(user_id)

    async def get_profile_by_email(self, email: str) -> UserProfile | None:
        user_id = generate_user_id(email)
        return _in_memory_profiles.get(user_id)

    async def update_profile(
        self,
        user_id: str,
        display_name: str | None = None,
        avatar_url: str | None = None,
        bio: str | None = None,
        timezone: str | None = None,
        preferred_currency: str | None = None,
    ) -> UserProfile:
        profile = await self.get_profile(user_id)
        if not profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User profile '{user_id}' not found.",
            )
        if display_name is not None:
            profile.display_name = display_name
        if avatar_url is not None:
            profile.avatar_url = avatar_url
        if bio is not None:
            profile.bio = bio
        if timezone is not None:
            profile.timezone = timezone
        if preferred_currency is not None:
            profile.preferred_currency = preferred_currency
        profile.updated_at = datetime.now(UTC).isoformat()
        _in_memory_profiles[user_id] = profile
        return profile

    async def change_account_status(
        self, user_id: str, new_status: AccountStatus, reason: str | None = None
    ) -> UserProfile:
        profile = await self.get_profile(user_id)
        if not profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User profile '{user_id}' not found.",
            )
        prev_status = profile.status
        profile.status = new_status
        profile.updated_at = datetime.now(UTC).isoformat()
        _in_memory_profiles[user_id] = profile

        # Revoke sessions & active tokens if suspended/deactivated/deleted
        if new_status in [
            AccountStatus.SUSPENDED,
            AccountStatus.DEACTIVATED,
            AccountStatus.DELETED,
        ]:
            await self.logout_all_devices(user_id)

        logger.info(
            f"User '{user_id}' status changed from '{prev_status.value}' to '{new_status.value}': {reason}"
        )
        return profile

    async def link_provider(
        self,
        user_id: str,
        provider: str,
        provider_user_id: str,
        email: str | None = None,
    ) -> UserProfile:
        profile = await self.get_profile(user_id)
        if not profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User profile '{user_id}' not found.",
            )
        for lp in profile.linked_providers:
            if lp.provider == provider and lp.provider_user_id == provider_user_id:
                return profile
        profile.linked_providers.append(
            LinkedProviderInfo(
                provider=provider,
                provider_user_id=provider_user_id,
                email=email,
                linked_at=datetime.now(UTC).isoformat(),
            )
        )
        profile.updated_at = datetime.now(UTC).isoformat()
        _in_memory_profiles[user_id] = profile
        return profile

    async def unlink_provider(self, user_id: str, provider: str) -> UserProfile:
        profile = await self.get_profile(user_id)
        if not profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User profile '{user_id}' not found.",
            )
        if len(profile.linked_providers) <= 1 and not profile.email_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot unlink the sole authentication method for this account.",
            )
        profile.linked_providers = [
            lp for lp in profile.linked_providers if lp.provider != provider
        ]
        profile.updated_at = datetime.now(UTC).isoformat()
        _in_memory_profiles[user_id] = profile
        return profile

    async def record_login_attempt(
        self,
        user_id: str,
        provider: str,
        ip_address: str,
        user_agent: str,
        status: str = "success",
        suspicious: bool = False,
        details: str | None = None,
    ) -> LoginHistoryEntry:
        entry = LoginHistoryEntry(
            id=f"log_{uuid.uuid4().hex[:12]}",
            user_id=user_id,
            timestamp=datetime.now(UTC).isoformat(),
            provider=provider,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
            suspicious=suspicious,
            details=details,
        )
        if user_id not in _in_memory_login_history:
            _in_memory_login_history[user_id] = []
        _in_memory_login_history[user_id].insert(0, entry)
        _in_memory_login_history[user_id] = _in_memory_login_history[user_id][:50]
        return entry

    async def get_login_history(
        self, user_id: str, limit: int = 20
    ) -> list[LoginHistoryEntry]:
        return _in_memory_login_history.get(user_id, [])[:limit]

    async def register_session(
        self,
        user_id: str,
        session_id: str,
        ip_address: str,
        user_agent: str,
        device_fingerprint: str | None = None,
        is_trusted: bool = False,
        ttl_seconds: int = 604800,
        tenant_id: str = "default",
    ) -> dict[str, Any]:
        now = time.time()
        now_str = datetime.now(UTC).isoformat()
        exp_str = datetime.fromtimestamp(now + ttl_seconds, UTC).isoformat()
        sess = {
            "session_id": session_id,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "ip_address": ip_address,
            "user_agent": user_agent,
            "device_fingerprint": device_fingerprint,
            "is_trusted": is_trusted,
            "created_at": now_str,
            "last_active_at": now_str,
            "expires_at": exp_str,
        }
        if user_id not in _in_memory_sessions:
            _in_memory_sessions[user_id] = []
        _in_memory_sessions[user_id].append(sess)

        r = await self._get_r()
        if r:
            idx_key = f"user_sessions:{tenant_id}:{user_id}"
            await r.sadd(idx_key, session_id)
            await r.expire(idx_key, ttl_seconds)
        return sess

    async def list_active_sessions(
        self, user_id: str, current_session_id: str | None = None
    ) -> list[ActiveSessionResponse]:
        sessions = _in_memory_sessions.get(user_id, [])
        res = []
        for s in sessions:
            res.append(
                ActiveSessionResponse(
                    session_id=s["session_id"],
                    user_id=s["user_id"],
                    ip_address=s["ip_address"],
                    user_agent=s["user_agent"],
                    device_fingerprint=s.get("device_fingerprint"),
                    is_trusted=s.get("is_trusted", False),
                    created_at=s["created_at"],
                    last_active_at=s["last_active_at"],
                    expires_at=s["expires_at"],
                    is_current=(s["session_id"] == current_session_id),
                )
            )
        return res

    async def revoke_session(
        self, user_id: str, session_id: str, tenant_id: str = "default"
    ) -> bool:
        if user_id in _in_memory_sessions:
            _in_memory_sessions[user_id] = [
                s for s in _in_memory_sessions[user_id] if s["session_id"] != session_id
            ]
        r = await self._get_r()
        if r:
            await r.setex(f"revoked:sid:{session_id}", 86400, "true")
            await r.srem(f"user_sessions:{tenant_id}:{user_id}", session_id)
        return True

    async def logout_all_devices(self, user_id: str, tenant_id: str = "default") -> int:
        count = len(_in_memory_sessions.get(user_id, []))
        _in_memory_sessions[user_id] = []
        r = await self._get_r()
        if r:
            now_ts = str(time.time())
            await r.setex(f"tokens_valid_after:{user_id}", 86400, now_ts)
            sids = await r.smembers(f"user_sessions:{tenant_id}:{user_id}")
            for sid in sids:
                await r.setex(f"revoked:sid:{sid}", 86400, "true")
            await r.delete(f"user_sessions:{tenant_id}:{user_id}")
        logger.info(f"User '{user_id}' logged out from all devices.")
        return max(count, 1)
