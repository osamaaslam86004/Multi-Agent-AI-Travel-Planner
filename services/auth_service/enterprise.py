"""
Enterprise Identity, SSO Domain Discovery, SAML 2.0, and SCIM 2.0 Provisioning Engine with DB Persistence.
"""

import logging
import uuid
from datetime import UTC, datetime

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
    db_delete_scim_user,
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

logger = logging.getLogger("travelbrain.auth.enterprise")

_in_memory_idp_configs: dict[str, IdPConfigResponse] = {}
_in_memory_scim_users: dict[str, SCIMUserSchema] = {}
_in_memory_scim_groups: dict[str, SCIMGroupSchema] = {}


class EnterpriseIdentityService:
    """Enterprise SSO and Domain Discovery Service."""

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

    async def get_idp_config(self, org_id: str) -> IdPConfigResponse | None:
        cfg = await db_get_idp_config(org_id)
        if cfg:
            return IdPConfigResponse(
                org_id=cfg["org_id"],
                idp_name=cfg["idp_name"],
                sso_type=cfg["sso_type"],
                issuer_url=cfg["issuer_url"],
                client_id=cfg["client_id"],
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
            enforce_sso=req.enforce_sso,
            allowed_domains=req.allowed_domains,
            group_role_mappings=req.group_role_mappings,
        )
        await db_save_idp_config(req.model_dump())
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
                assigned_roles.add(config.group_role_mappings[grp])
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
            user_objects = list(_in_memory_scim_users.values())

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
        await db_save_scim_user(user_data.model_dump(), org_id=org_id)
        _in_memory_scim_users[user_id] = user_data
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
        return _in_memory_scim_users.get(user_id)

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
        _in_memory_scim_users[user_id] = user_data
        return user_data

    async def delete_user(self, user_id: str, org_id: str | None = None) -> bool:
        success = await db_delete_scim_user(user_id, org_id=org_id)
        _in_memory_scim_users.pop(user_id, None)
        logger.info(f"SCIM Deprovisioned User '{user_id}'")
        return success

    async def list_groups(self, org_id: str | None = None) -> SCIMListResponse:
        db_groups = await db_list_scim_groups(org_id=org_id)
        grp_objects = []
        for g_dict in db_groups:
            try:
                grp_objects.append(SCIMGroupSchema(**g_dict))
            except Exception:
                pass
        if not grp_objects:
            grp_objects = list(_in_memory_scim_groups.values())
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
        _in_memory_scim_groups[grp_id] = group_data
        return group_data

    async def get_group(
        self, group_id: str, org_id: str | None = None
    ) -> SCIMGroupSchema | None:
        g_dict = await db_get_scim_group(group_id, org_id=org_id)
        if g_dict:
            return SCIMGroupSchema(**g_dict)
        return _in_memory_scim_groups.get(group_id)

    async def delete_group(self, group_id: str, org_id: str | None = None) -> bool:
        success = await db_delete_scim_group(group_id, org_id=org_id)
        _in_memory_scim_groups.pop(group_id, None)
        return success


enterprise_service = EnterpriseIdentityService()
scim_service = SCIM2Service()
