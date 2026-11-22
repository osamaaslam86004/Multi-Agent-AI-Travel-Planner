"""
User Account Lifecycle Management Service.
Handles user profiles, account state transitions, identity provider linking,
login history tracking, active sessions, and multi-device logout with database persistence.
"""

import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from services.auth_service.models import (
    AccountStatus,
    ActiveSessionResponse,
    LinkedProviderInfo,
    LoginHistoryEntry,
    UserProfile,
)
from services.auth_service.security import generate_user_id
from services.common.db import (
    db_get_federated_identity,
    db_get_user_by_email,
    db_get_user_by_id,
    db_link_federated_identity,
    db_upsert_user_profile,
)
from services.shared.redis_client import get_redis_client

logger = logging.getLogger("travelbrain.auth.user_lifecycle")

_in_memory_profiles: dict[str, UserProfile] = {}
_in_memory_login_history: dict[str, list[LoginHistoryEntry]] = {}
_in_memory_sessions: dict[str, list[dict[str, Any]]] = {}


class UserLifecycleService:
    """Core User Profile and Account Lifecycle Service with Postgres persistence."""

    def __init__(self, redis_client: Any = None):
        self.redis = redis_client

    async def get_or_create_profile(
        self,
        email: str,
        tenant_id: str = "default",
        auth_provider: str = "direct",
        display_name: str | None = None,
        provider_sub: str | None = None,
        issuer: str | None = None,
    ) -> UserProfile:
        email_clean = email.lower().strip()
        now_str = datetime.now(UTC).isoformat()

        # Action Item 6: First check if user is linked via federated identity
        existing_fed = None
        if provider_sub:
            iss = issuer or auth_provider
            existing_fed = await db_get_federated_identity(
                auth_provider, iss, provider_sub
            )

        existing_user_dict = None
        if existing_fed:
            existing_user_dict = await db_get_user_by_id(existing_fed["user_id"])
        if not existing_user_dict:
            existing_user_dict = await db_get_user_by_email(email_clean)

        if existing_user_dict:
            user_id = existing_user_dict["user_id"]
            profile = UserProfile(
                user_id=user_id,
                email=existing_user_dict["email"],
                display_name=existing_user_dict.get("display_name")
                or email_clean.split("@")[0].title(),
                avatar_url=existing_user_dict.get("avatar_url"),
                bio=existing_user_dict.get("bio"),
                timezone=existing_user_dict.get("timezone", "UTC"),
                preferred_currency=existing_user_dict.get("preferred_currency", "USD"),
                tenant_id=existing_user_dict.get("tenant_id", tenant_id),
                org_id=existing_user_dict.get("org_id"),
                status=AccountStatus(existing_user_dict.get("status", "active")),
                roles=existing_user_dict.get("roles", ["member"]),
                email_verified=existing_user_dict.get("email_verified", True),
                mfa_enabled=existing_user_dict.get("mfa_enabled", False),
                created_at=existing_user_dict.get("created_at", now_str),
                updated_at=now_str,
            )
        else:
            # Action Item 6: Generate internal random user_id (usr_{uuid4})
            user_id = generate_user_id(email_clean)
            profile = UserProfile(
                user_id=user_id,
                email=email_clean,
                display_name=display_name or email_clean.split("@")[0].title(),
                tenant_id=tenant_id,
                status=AccountStatus.ACTIVE,
                email_verified=(auth_provider != "direct"),
                created_at=now_str,
                updated_at=now_str,
            )

        if auth_provider != "direct":
            sub_val = provider_sub or user_id
            iss_val = issuer or auth_provider
            await db_link_federated_identity(
                user_id=user_id,
                provider=auth_provider,
                issuer=iss_val,
                sub=sub_val,
                email=email_clean,
                email_verified=profile.email_verified,
            )
            already_linked = any(
                lp.provider == auth_provider and lp.provider_user_id == sub_val
                for lp in profile.linked_providers
            )
            if not already_linked:
                profile.linked_providers.append(
                    LinkedProviderInfo(
                        provider=auth_provider,
                        provider_user_id=sub_val,
                        email=email_clean,
                        linked_at=now_str,
                    )
                )

        # Action Item 1: Persist to database repository
        await db_upsert_user_profile(profile.model_dump())
        _in_memory_profiles[user_id] = profile
        return profile

    async def get_profile(self, user_id: str) -> UserProfile | None:
        user_dict = await db_get_user_by_id(user_id)
        if user_dict:
            return UserProfile(
                user_id=user_dict["user_id"],
                email=user_dict["email"],
                display_name=user_dict.get("display_name"),
                avatar_url=user_dict.get("avatar_url"),
                bio=user_dict.get("bio"),
                timezone=user_dict.get("timezone", "UTC"),
                preferred_currency=user_dict.get("preferred_currency", "USD"),
                tenant_id=user_dict.get("tenant_id", "default"),
                org_id=user_dict.get("org_id"),
                status=AccountStatus(user_dict.get("status", "active")),
                roles=user_dict.get("roles", ["member"]),
                email_verified=user_dict.get("email_verified", False),
                mfa_enabled=user_dict.get("mfa_enabled", False),
                created_at=user_dict.get("created_at"),
                updated_at=user_dict.get("updated_at"),
            )
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
            raise ValueError(f"User profile '{user_id}' not found")
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

        await db_upsert_user_profile(profile.model_dump())
        _in_memory_profiles[user_id] = profile
        return profile

    async def change_account_status(
        self, user_id: str, new_status: AccountStatus, reason: str | None = None
    ) -> UserProfile:
        profile = await self.get_profile(user_id)
        if not profile:
            raise ValueError(f"User profile '{user_id}' not found")
        profile.status = new_status
        profile.updated_at = datetime.now(UTC).isoformat()
        if new_status in [
            AccountStatus.SUSPENDED,
            AccountStatus.DEACTIVATED,
            AccountStatus.DELETED,
        ]:
            await self.logout_all_devices(user_id)
        await db_upsert_user_profile(profile.model_dump())
        _in_memory_profiles[user_id] = profile
        logger.info(
            f"User '{user_id}' status changed to '{new_status.value}': {reason}"
        )
        return profile

    async def link_provider(
        self,
        user_id: str,
        provider: str,
        provider_user_id: str,
        email: str | None = None,
        issuer: str | None = None,
    ) -> UserProfile:
        profile = await self.get_profile(user_id)
        if not profile:
            raise ValueError(f"User profile '{user_id}' not found")

        iss = issuer or provider
        await db_link_federated_identity(
            user_id=user_id,
            provider=provider,
            issuer=iss,
            sub=provider_user_id,
            email=email or profile.email,
            email_verified=True,
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
        await db_upsert_user_profile(profile.model_dump())
        _in_memory_profiles[user_id] = profile
        return profile

    async def unlink_provider(self, user_id: str, provider: str) -> UserProfile:
        profile = await self.get_profile(user_id)
        if not profile:
            raise ValueError(f"User profile '{user_id}' not found")
        profile.linked_providers = [
            lp for lp in profile.linked_providers if lp.provider != provider
        ]
        profile.updated_at = datetime.now(UTC).isoformat()
        await db_upsert_user_profile(profile.model_dump())
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

    async def revoke_session(self, user_id: str, session_id: str) -> bool:
        if user_id in _in_memory_sessions:
            _in_memory_sessions[user_id] = [
                s for s in _in_memory_sessions[user_id] if s["session_id"] != session_id
            ]
        r = await get_redis_client()
        if r:
            await r.setex(f"revoked:sid:{session_id}", 86400, "true")
        return True

    async def logout_all_devices(self, user_id: str) -> int:
        count = len(_in_memory_sessions.get(user_id, []))
        _in_memory_sessions[user_id] = []
        r = await get_redis_client()
        if r:
            await r.set(f"tokens_valid_after:{user_id}", str(time.time()))
        logger.info(f"User '{user_id}' logged out from all {count} devices.")
        return count


lifecycle_service = UserLifecycleService()
