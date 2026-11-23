"""
Enterprise Identity, SSO Domain Discovery, SAML 2.0, and SCIM 2.0 Provisioning Engine with DB Persistence.
"""

import base64
import hashlib
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from cryptography.fernet import Fernet

from services.auth_service.models import (
    IdPConfigRequest,
    IdPConfigResponse,
    OrgSSODiscoveryResponse,
    SCIMGroupSchema,
    SCIMListResponse,
    SCIMMeta,
    SCIMUserSchema,
)
from services.auth_service.security import generate_user_id
from services.common.db import (
    db_delete_scim_group,
    db_get_idp_config,
    db_get_scim_group,
    db_get_scim_user,
    db_list_all_idp_configs,
    db_list_scim_groups,
    db_list_scim_users,
    db_save_idp_config,
    db_save_scim_group,
    db_save_scim_user,
)
from services.core.config import get_settings

logger = logging.getLogger("travelbrain.auth.enterprise")
_in_memory_idp_configs: dict[str, IdPConfigResponse] = {}
_in_memory_scim_users: dict[str, SCIMUserSchema] = {}
_in_memory_scim_groups: dict[str, SCIMGroupSchema] = {}


class EnterpriseIdentityService:
    """Enterprise SSO and Domain Discovery Service."""

    def _secret_cipher(self) -> Fernet:
        settings = get_settings()
        configured = settings.auth.identity_encryption_key
        if configured:
            try:
                return Fernet(configured.encode())
            except Exception as exc:
                raise RuntimeError(
                    "IDENTITY_ENCRYPTION_KEY must be a valid Fernet key"
                ) from exc
        if settings.app.environment.lower() in ("production", "staging"):
            raise RuntimeError(
                "IDENTITY_ENCRYPTION_KEY is required in production/staging"
            )
        master = settings.auth.jwt_secret_key.encode("utf-8")
        key = base64.urlsafe_b64encode(
            hashlib.sha256(master + b"|identity-secrets").digest()
        )
        return Fernet(key)

    def _encrypt_client_secret(self, value: str | None) -> str | None:
        if not value:
            return value
        return "enc:v1:" + self._secret_cipher().encrypt(value.encode()).decode()

    def _decrypt_client_secret(self, value: str | None) -> str | None:
        if not value:
            return value
        if value.startswith("enc:v1:"):
            return self._secret_cipher().decrypt(value[7:].encode()).decode()
        # Legacy plaintext records are accepted only for migration; new writes are encrypted.
        return value

    async def get_idp_config_raw(self, org_id: str) -> dict[str, Any] | None:
        cfg = await db_get_idp_config(org_id)
        if not cfg:
            return None
        cfg["client_secret"] = self._decrypt_client_secret(cfg.get("client_secret"))
        return cfg

    async def discover_sso_by_domain(
        self, email: str
    ) -> OrgSSODiscoveryResponse | None:
        domain = email.split("@")[-1].lower().strip() if "@" in email else ""
        if not domain:
            return None
        configs = await db_list_all_idp_configs()
        for config_dict in configs:
            allowed_domains = config_dict.get("allowed_domains", [])
            org_id = config_dict["org_id"]
            if domain in allowed_domains:
                return OrgSSODiscoveryResponse(
                    org_id=org_id,
                    org_name=f"Enterprise Org ({domain})",
                    sso_enforced=config_dict.get("enforce_sso", False),
                    sso_type=config_dict.get("sso_type", "oidc"),
                    login_url=f"https://auth.travelbrain.ai/api/v1/auth/{config_dict.get('sso_type')}/login?org_id={org_id}",
                )
        return None

    async def list_idp_configs(self) -> list[IdPConfigResponse]:
        configs = await db_list_all_idp_configs()
        output = []
        for item in configs:
            try:
                output.append(IdPConfigResponse(**item))
            except Exception:
                logger.warning(
                    "Skipping invalid IdP config record for org %s", item.get("org_id")
                )
        # Only use process-local configs in development; DB is authoritative when configured.
        if not output:
            output = list(_in_memory_idp_configs.values())
        return output

    async def get_idp_config(self, org_id: str) -> IdPConfigResponse | None:
        cfg = await db_get_idp_config(org_id)
        if cfg:
            return IdPConfigResponse(
                org_id=cfg["org_id"],
                idp_name=cfg["idp_name"],
                sso_type=cfg["sso_type"],
                issuer_url=cfg["issuer_url"],
                client_id=cfg["client_id"],
                metadata_xml=cfg.get("metadata_xml"),
                enforce_sso=cfg.get("enforce_sso", False),
                allowed_domains=cfg.get("allowed_domains", []),
                group_role_mappings=cfg.get("group_role_mappings", {}),
            )
        return _in_memory_idp_configs.get(org_id)

    async def set_idp_config(self, req: IdPConfigRequest) -> IdPConfigResponse:
        cfg = IdPConfigResponse(
            org_id=req.org_id,
            idp_name=req.idp_name,
            sso_type=req.sso_type,
            issuer_url=req.issuer_url,
            client_id=req.client_id,
            metadata_xml=req.metadata_xml,
            enforce_sso=req.enforce_sso,
            allowed_domains=req.allowed_domains,
            group_role_mappings=req.group_role_mappings,
        )
        stored = req.model_dump()
        stored["client_secret"] = self._encrypt_client_secret(
            stored.get("client_secret")
        )
        await db_save_idp_config(stored)
        _in_memory_idp_configs[req.org_id] = cfg
        logger.info(f"Updated IdP config for org '{req.org_id}'")
        return cfg

    async def map_idp_groups_to_roles(
        self, org_id: str, idp_groups: list[str]
    ) -> list[str]:
        config = await self.get_idp_config(org_id)
        if not config or not config.group_role_mappings:
            return ["member"]
        assigned_roles = set()
        for grp in idp_groups:
            if grp in config.group_role_mappings:
                role = config.group_role_mappings[grp]
                from services.auth_service.rbac import ROLES_CATALOG

                if role in ROLES_CATALOG and ROLES_CATALOG[role].scope in {
                    "tenant",
                    "organization",
                }:
                    assigned_roles.add(role)
                else:
                    logger.warning(
                        "Ignoring invalid IdP role mapping for group %s", grp
                    )
        return list(assigned_roles) if assigned_roles else ["member"]


class SCIM2Service:
    """SCIM 2.0 Protocol User & Group Provisioning Service with DB Persistence."""

    async def list_users(
        self,
        org_id: str | None = None,
        filter_query: str | None = None,
        start_index: int = 1,
        count: int = 100,
    ) -> SCIMListResponse:
        db_users = await db_list_scim_users(org_id=org_id)
        user_objects = []
        for u_dict in db_users:
            try:
                user_objects.append(SCIMUserSchema(**u_dict))
            except Exception:
                pass
        if not user_objects:
            prefix = f"{org_id}:" if org_id else ""
            user_objects = [
                value
                for key, value in _in_memory_scim_users.items()
                if not prefix or key.startswith(prefix)
            ]
        if filter_query and "userName eq" in filter_query:
            target_email = (
                filter_query.split("userName eq")[-1].replace('"', "").strip()
            )
            user_objects = [
                u for u in user_objects if u.userName.lower() == target_email.lower()
            ]
        return SCIMListResponse(
            totalResults=len(user_objects),
            startIndex=start_index,
            itemsPerPage=count,
            Resources=user_objects[start_index - 1 : start_index - 1 + count],
        )

    async def create_user(
        self, user_data: SCIMUserSchema, org_id: str | None = None
    ) -> SCIMUserSchema:
        user_id = generate_user_id(user_data.userName)
        now_str = datetime.now(UTC).isoformat()
        user_data.id = user_id
        user_data.meta = SCIMMeta(
            resourceType="User",
            created=now_str,
            lastModified=now_str,
            location=f"/scim/v2/Users/{user_id}",
        )
        if "@" not in user_data.userName:
            raise ValueError(
                "SCIM userName must be an email address for account synchronization"
            )
        await db_save_scim_user(user_data.model_dump(), org_id=org_id)
        _in_memory_scim_users[f"{org_id or 'default'}:{user_id}"] = user_data
        from services.auth_service.models import AccountStatus
        from services.auth_service.user_lifecycle import lifecycle_service
        from services.common.db import db_upsert_user_profile

        profile = await lifecycle_service.get_or_create_profile(
            user_data.userName, auth_provider="scim", tenant_id="default"
        )
        if profile.org_id and profile.org_id != org_id:
            raise ValueError("SCIM user already belongs to another organization")
        profile.org_id = org_id
        profile.display_name = user_data.displayName or profile.display_name
        profile.status = (
            AccountStatus.ACTIVE if user_data.active else AccountStatus.DEACTIVATED
        )
        profile.updated_at = datetime.now(UTC).isoformat()
        await db_upsert_user_profile(profile.model_dump())
        if not user_data.active:
            await lifecycle_service.logout_all_devices(profile.user_id)
        logger.info(
            f"SCIM Provisioned User '{user_data.userName}' ({user_id}) for org '{org_id}'"
        )
        return user_data

    async def get_user(
        self, user_id: str, org_id: str | None = None
    ) -> SCIMUserSchema | None:
        u_dict = await db_get_scim_user(user_id, org_id=org_id)
        if u_dict:
            return SCIMUserSchema(**u_dict)
        return _in_memory_scim_users.get(f"{org_id or 'default'}:{user_id}")

    async def update_user(
        self, user_id: str, user_data: SCIMUserSchema, org_id: str | None = None
    ) -> SCIMUserSchema:
        user_data.id = user_id
        user_data.meta = SCIMMeta(
            resourceType="User",
            lastModified=datetime.now(UTC).isoformat(),
            location=f"/scim/v2/Users/{user_id}",
        )
        await db_save_scim_user(user_data.model_dump(), org_id=org_id)
        _in_memory_scim_users[f"{org_id or 'default'}:{user_id}"] = user_data
        await self._sync_internal_user_status(
            user_data.userName, user_data.active, org_id
        )
        return user_data

    async def delete_user(self, user_id: str, org_id: str | None = None) -> bool:
        existing = await self.get_user(user_id, org_id=org_id)
        if not existing:
            return False
        existing.active = False
        existing.meta = SCIMMeta(
            resourceType="User",
            lastModified=datetime.now(UTC).isoformat(),
            location=f"/scim/v2/Users/{user_id}",
        )
        await db_save_scim_user(existing.model_dump(), org_id=org_id)
        _in_memory_scim_users[f"{org_id or 'default'}:{user_id}"] = existing
        await self._sync_internal_user_status(existing.userName, False, org_id)
        logger.info("SCIM deprovisioned user %s in org %s", user_id, org_id)
        return True

    async def _sync_internal_user_status(
        self, username: str, active: bool, org_id: str | None
    ) -> None:
        from services.auth_service.models import AccountStatus
        from services.auth_service.user_lifecycle import lifecycle_service
        from services.common.db import db_get_user_by_email, db_upsert_user_profile

        profile_data = await db_get_user_by_email(username.lower().strip())
        if not profile_data:
            return
        profile = await lifecycle_service.get_profile(profile_data["user_id"])
        if profile and (profile.org_id is None or profile.org_id == org_id):
            profile.status = (
                AccountStatus.ACTIVE if active else AccountStatus.DEACTIVATED
            )
            profile.updated_at = datetime.now(UTC).isoformat()
            await db_upsert_user_profile(profile.model_dump())
            if not active:
                await lifecycle_service.logout_all_devices(profile.user_id)

    async def list_groups(self, org_id: str | None = None) -> SCIMListResponse:
        db_groups = await db_list_scim_groups(org_id=org_id)
        grp_objects = []
        for g_dict in db_groups:
            try:
                grp_objects.append(SCIMGroupSchema(**g_dict))
            except Exception:
                pass
        if not grp_objects:
            prefix = f"{org_id}:" if org_id else ""
            grp_objects = [
                value
                for key, value in _in_memory_scim_groups.items()
                if not prefix or key.startswith(prefix)
            ]
        return SCIMListResponse(
            totalResults=len(grp_objects),
            startIndex=1,
            itemsPerPage=100,
            Resources=grp_objects,
        )

    async def create_group(
        self, group_data: SCIMGroupSchema, org_id: str | None = None
    ) -> SCIMGroupSchema:
        grp_id = f"grp_{uuid.uuid4().hex[:12]}"
        now_str = datetime.now(UTC).isoformat()
        group_data.id = grp_id
        group_data.meta = SCIMMeta(
            resourceType="Group",
            created=now_str,
            lastModified=now_str,
            location=f"/scim/v2/Groups/{grp_id}",
        )
        await db_save_scim_group(group_data.model_dump(), org_id=org_id)
        _in_memory_scim_groups[f"{org_id or 'default'}:{grp_id}"] = group_data
        return group_data

    async def update_group(
        self, group_id: str, group_data: SCIMGroupSchema, org_id: str | None = None
    ) -> SCIMGroupSchema:
        current = await self.get_group(group_id, org_id=org_id)
        if not current:
            raise ValueError("SCIM group not found")
        group_data.id = group_id
        group_data.meta = SCIMMeta(
            resourceType="Group",
            lastModified=datetime.now(UTC).isoformat(),
            location=f"/scim/v2/Groups/{group_id}",
        )
        await db_save_scim_group(group_data.model_dump(), org_id=org_id)
        _in_memory_scim_groups[f"{org_id or 'default'}:{group_id}"] = group_data
        return group_data

    async def get_group(
        self, group_id: str, org_id: str | None = None
    ) -> SCIMGroupSchema | None:
        g_dict = await db_get_scim_group(group_id, org_id=org_id)
        if g_dict:
            return SCIMGroupSchema(**g_dict)
        return _in_memory_scim_groups.get(f"{org_id or 'default'}:{group_id}")

    async def delete_group(self, group_id: str, org_id: str | None = None) -> bool:
        success = await db_delete_scim_group(group_id, org_id=org_id)
        _in_memory_scim_groups.pop(f"{org_id or 'default'}:{group_id}", None)
        return success


enterprise_service = EnterpriseIdentityService()
scim_service = SCIM2Service()
