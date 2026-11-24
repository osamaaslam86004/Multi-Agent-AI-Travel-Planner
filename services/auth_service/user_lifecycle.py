"""
User Account Lifecycle Management Service.
Handles user profiles, account state transitions, identity provider linking,
login history tracking, active sessions, invitations, grace period soft-deletion, and multi-device logout with database persistence.
"""

import logging
import os
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from services.auth_service.models import (
    AccountStatus,
    ActiveSessionResponse,
    InvitationResponse,
    LinkedProviderInfo,
    LoginHistoryEntry,
    UserProfile,
)
from services.auth_service.security import generate_user_id
from services.common.db import (
    db_accept_invitation,
    db_add_org_membership,
    db_get_federated_identity,
    db_get_invitation,
    db_get_login_history,
    db_get_user_by_email,
    db_get_user_by_id,
    db_get_user_linked_providers,
    db_get_user_password,
    db_link_federated_identity,
    db_record_login_history,
    db_save_invitation,
    db_save_user_password,
    db_unlink_federated_identity,
    db_upsert_user_profile,
    init_db_pool,
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
        iss_val = issuer or auth_provider
        existing_fed = None
        if provider_sub:
            existing_fed = await db_get_federated_identity(
                auth_provider, iss_val, provider_sub
            )
        existing_user_dict = None
        if existing_fed:
            existing_user_dict = await db_get_user_by_id(existing_fed["user_id"])
        if not existing_user_dict:
            existing_user_dict = await db_get_user_by_email(
                email_clean, tenant_id=tenant_id
            )
        if existing_user_dict:
            user_id = existing_user_dict["user_id"]
            linked_rows = await db_get_user_linked_providers(user_id)
            linked_infos = [
                LinkedProviderInfo(
                    provider=r["provider"],
                    provider_user_id=r["provider_user_id"],
                    email=r.get("email"),
                    linked_at=r["linked_at"],
                )
                for r in linked_rows
            ]
            profile = UserProfile(
                user_id=user_id,
                email=existing_user_dict["email"],
                display_name=existing_user_dict.get("display_name")
                or display_name
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
                linked_providers=linked_infos,
                created_at=existing_user_dict.get("created_at", now_str),
                updated_at=now_str,
            )
        else:
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
        await db_upsert_user_profile(profile.model_dump())
        _in_memory_profiles[user_id] = profile
        return profile

    async def get_profile(
        self, user_id: str, tenant_id: str | None = None
    ) -> UserProfile | None:
        user_dict = await db_get_user_by_id(user_id, tenant_id=tenant_id)
        if user_dict:
            linked_rows = await db_get_user_linked_providers(user_id)
            linked_infos = [
                LinkedProviderInfo(
                    provider=r["provider"],
                    provider_user_id=r["provider_user_id"],
                    email=r.get("email"),
                    linked_at=r["linked_at"],
                )
                for r in linked_rows
            ]
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
                linked_providers=linked_infos,
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
            AccountStatus.PENDING_DELETION,
        ]:
            await self.logout_all_devices(user_id)
        await db_upsert_user_profile(profile.model_dump())
        _in_memory_profiles[user_id] = profile
        logger.info(
            f"User '{user_id}' status changed to '{new_status.value}': {reason}"
        )
        return profile

    async def schedule_account_deletion(
        self, user_id: str, grace_period_days: int = 30
    ) -> UserProfile:
        profile = await self.get_profile(user_id)
        if not profile:
            raise ValueError(f"User profile '{user_id}' not found")
        now = datetime.now(UTC)
        sched = now + timedelta(days=grace_period_days)
        profile.status = AccountStatus.PENDING_DELETION
        profile.updated_at = now.isoformat()
        p_dict = profile.model_dump()
        p_dict["deletion_requested_at"] = now.isoformat()
        p_dict["deletion_scheduled_at"] = sched.isoformat()
        await db_upsert_user_profile(p_dict)
        await self.logout_all_devices(user_id)
        _in_memory_profiles[user_id] = profile
        logger.info(
            f"Scheduled soft-deletion for user '{user_id}' at {sched.isoformat()}"
        )
        return profile

    async def cancel_account_deletion(self, user_id: str) -> UserProfile:
        profile = await self.get_profile(user_id)
        if not profile:
            raise ValueError(f"User profile '{user_id}' not found")
        if profile.status != AccountStatus.PENDING_DELETION:
            raise ValueError("Account is not pending deletion")
        profile.status = AccountStatus.ACTIVE
        profile.updated_at = datetime.now(UTC).isoformat()
        p_dict = profile.model_dump()
        p_dict["deletion_requested_at"] = None
        p_dict["deletion_scheduled_at"] = None
        await db_upsert_user_profile(p_dict)
        _in_memory_profiles[user_id] = profile
        logger.info(f"Cancelled soft-deletion for user '{user_id}'")
        return profile

    async def cleanup_expired_deleted_accounts(self) -> int:
        """Background worker step: hard-deletes & anonymizes accounts past their grace period."""
        datetime.now(UTC).isoformat()
        cleaned_count = 0
        pool = await init_db_pool()
        if pool is not None:
            async with pool.connection() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT user_id, email FROM user_profiles WHERE status = 'pending_deletion' "
                        "AND deletion_scheduled_at <= NOW();"
                    )
                    rows = await cur.fetchall()
                    for r in rows:
                        uid, _email = r[0], r[1]
                        anon_email = f"deleted_{uuid.uuid4().hex[:8]}@anonymized.local"
                        await cur.execute(
                            "UPDATE user_profiles SET email = %s, display_name = 'Deleted User', "
                            "avatar_url = NULL, bio = NULL, status = 'deleted', updated_at = NOW() "
                            "WHERE user_id = %s;",
                            (anon_email, uid),
                        )
                        await cur.execute(
                            "DELETE FROM user_credentials WHERE user_id = %s;", (uid,)
                        )
                        await cur.execute(
                            "DELETE FROM federated_identities WHERE user_id = %s;",
                            (uid,),
                        )
                        cleaned_count += 1
                await conn.commit()
            return cleaned_count
        for uid, p in list(_in_memory_profiles.items()):
            if p.status == AccountStatus.PENDING_DELETION:
                p.status = AccountStatus.DELETED
                p.display_name = "Deleted User"
                p.email = f"deleted_{uuid.uuid4().hex[:8]}@anonymized.local"
                p.linked_providers = []
                cleaned_count += 1
        return cleaned_count

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
        provider_links = [
            lp for lp in profile.linked_providers if lp.provider != provider
        ]
        password_hash = await db_get_user_password(user_id)
        if not provider_links and not password_hash:
            raise ValueError("Cannot unlink the user's only authentication method.")
        removed = await db_unlink_federated_identity(user_id, provider)
        if removed == 0:
            raise ValueError("No federated identity record exists for this provider.")
        profile.linked_providers = provider_links
        profile.updated_at = datetime.now(UTC).isoformat()
        await db_upsert_user_profile(profile.model_dump())
        _in_memory_profiles[user_id] = profile
        return profile

    async def create_invitation(
        self,
        email: str,
        org_id: str,
        role: str,
        created_by: str,
        expires_in_days: int = 7,
    ) -> InvitationResponse:
        # Cap expiry to 30 days max
        expires_in_days = min(max(1, expires_in_days), 30)
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        expires_at = (datetime.now(UTC) + timedelta(days=expires_in_days)).isoformat()
        # Save token_hash to DB
        await db_save_invitation(
            token_hash, email, org_id, role, created_by, expires_at
        )
        # Optionally send invitation email if mailer configured
        try:
            from services.common.mailer import send_invitation_email

            await send_invitation_email(email, token, org_id, role)
        except Exception as e:
            logger.warning(f"Could not send invitation email to {email}: {e}")
        return InvitationResponse(
            token=token,
            email=email.lower().strip(),
            org_id=org_id,
            role=role,
            expires_at=expires_at,
        )

    async def get_invitation(self, token: str) -> dict[str, Any] | None:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        inv = await db_get_invitation(token_hash)
        if not inv:
            # Fallback for unhashed token lookup
            inv = await db_get_invitation(token)
        if not inv:
            return None
        if inv.get("accepted"):
            raise ValueError("Invitation has already been accepted")
        exp = inv.get("expires_at")
        if exp and datetime.fromisoformat(str(exp)) < datetime.now(UTC):
            raise ValueError("Invitation token has expired")
        return inv

    async def accept_invitation(
        self, token: str, password: str | None = None, display_name: str | None = None
    ) -> UserProfile:
        inv = await self.get_invitation(token)
        if not inv:
            raise ValueError("Invalid invitation token")
        email = inv["email"]
        org_id = inv["org_id"]
        role = inv["role"]
        existing_user = await db_get_user_by_email(email)
        profile = await self.get_or_create_profile(
            email=email, display_name=display_name, auth_provider="invitation"
        )
        # STOP password replacement on existing accounts:
        # Only allow setting password if the user did NOT already exist prior to invitation
        if password:
            if existing_user:
                logger.warning(
                    f"Prevented password overwrite during invitation accept for existing user {email}"
                )
            else:
                from services.auth_service.security import hash_password

                await db_save_user_password(profile.user_id, hash_password(password))
        profile.org_id = org_id
        if role not in profile.roles:
            profile.roles.append(role)
        profile.updated_at = datetime.now(UTC).isoformat()
        await db_upsert_user_profile(profile.model_dump())
        await db_add_org_membership(profile.user_id, org_id, role)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        await db_accept_invitation(token_hash)
        await db_accept_invitation(token)
        return profile

    async def schedule_account_deletion(self, user_id: str) -> tuple[UserProfile, str]:
        profile = await self.get_profile(user_id)
        if not profile:
            raise ValueError(f"User profile '{user_id}' not found")
        now = datetime.now(UTC)
        scheduled_at = now + timedelta(days=30)
        profile.status = AccountStatus.PENDING_DELETION
        profile.deletion_requested_at = now.isoformat()
        profile.deletion_scheduled_at = scheduled_at.isoformat()
        profile.updated_at = now.isoformat()
        await db_upsert_user_profile(profile.model_dump())
        await self.logout_all_devices(user_id)
        cancel_token = secrets.token_urlsafe(32)
        c_hash = hashlib.sha256(cancel_token.encode("utf-8")).hexdigest()
        from services.common.db import db_save_cancellation_token

        await db_save_cancellation_token(c_hash, user_id, scheduled_at.isoformat())
        return profile, cancel_token

    async def cancel_account_deletion(
        self, user_id: str | None = None, cancellation_token: str | None = None
    ) -> UserProfile:
        target_uid = user_id
        if cancellation_token:
            c_hash = hashlib.sha256(cancellation_token.encode("utf-8")).hexdigest()
            from services.common.db import (
                db_delete_cancellation_token,
                db_get_cancellation_token,
            )

            c_rec = await db_get_cancellation_token(c_hash)
            if not c_rec:
                raise ValueError(
                    "Invalid or expired account deletion cancellation token"
                )
            target_uid = c_rec["user_id"]
            await db_delete_cancellation_token(c_hash)
        if not target_uid:
            raise ValueError(
                "User ID or cancellation token required to cancel deletion"
            )
        profile = await self.get_profile(target_uid)
        if not profile:
            raise ValueError(f"User profile '{target_uid}' not found")
        profile.status = AccountStatus.ACTIVE
        profile.deletion_requested_at = None
        profile.deletion_scheduled_at = None
        profile.updated_at = datetime.now(UTC).isoformat()
        await db_upsert_user_profile(profile.model_dump())
        return profile

    async def cleanup_expired_deleted_accounts(self) -> int:
        """Background worker step: hard-deletes & anonymizes accounts past their 30-day grace period."""
        now_iso = datetime.now(UTC).isoformat()
        cleaned_count = 0
        pool = await init_db_pool()
        if pool is not None:
            async with pool.connection() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT user_id, email FROM user_profiles WHERE status = 'pending_deletion' "
                        "AND deletion_scheduled_at <= NOW();"
                    )
                    rows = await cur.fetchall()
                    for r in rows:
                        uid, _email = r[0], r[1]
                        anon_email = f"deleted_{uuid.uuid4().hex[:8]}@anonymized.local"
                        await cur.execute(
                            "UPDATE user_profiles SET email = %s, display_name = 'Deleted User', "
                            "avatar_url = NULL, bio = NULL, status = 'deleted', updated_at = NOW() "
                            "WHERE user_id = %s;",
                            (anon_email, uid),
                        )
                        await cur.execute(
                            "DELETE FROM user_credentials WHERE user_id = %s;", (uid,)
                        )
                        await cur.execute(
                            "DELETE FROM federated_identities WHERE user_id = %s;",
                            (uid,),
                        )
                        cleaned_count += 1
                await conn.commit()
            return cleaned_count
        for uid, p in list(_in_memory_profiles.items()):
            if p.status == AccountStatus.PENDING_DELETION:
                if p.deletion_scheduled_at and p.deletion_scheduled_at <= now_iso:
                    p.status = AccountStatus.DELETED
                    p.display_name = "Deleted User"
                    p.email = f"deleted_{uuid.uuid4().hex[:8]}@anonymized.local"
                    p.linked_providers = []
                    cleaned_count += 1
        return cleaned_count

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
        await db_record_login_history(entry.model_dump())
        if user_id not in _in_memory_login_history:
            _in_memory_login_history[user_id] = []
        _in_memory_login_history[user_id].insert(0, entry)
        _in_memory_login_history[user_id] = _in_memory_login_history[user_id][:50]
        return entry

    async def get_login_history(
        self, user_id: str, limit: int = 20
    ) -> list[LoginHistoryEntry]:
        rows = await db_get_login_history(user_id, limit=limit)
        if rows:
            return [LoginHistoryEntry(**row) for row in rows]
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
        if r is None and os.getenv("ENVIRONMENT", "development").lower() in (
            "production",
            "staging",
        ):
            raise RuntimeError("Distributed revocation state unavailable")
        if r:
            await r.set(f"tokens_valid_after:{user_id}", str(time.time()))
        logger.info(f"User '{user_id}' logged out from all {count} devices.")
        return count


lifecycle_service = UserLifecycleService()
