"""
Enterprise Identity, SSO Domain Discovery, SAML 2.0, and SCIM 2.0 Provisioning Engine.
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

logger = logging.getLogger("travelbrain.auth.enterprise")

_in_memory_idp_configs: dict[str, IdPConfigResponse] = {}
_in_memory_scim_users: dict[str, SCIMUserSchema] = {}
_in_memory_scim_groups: dict[str, SCIMGroupSchema] = {}


class EnterpriseIdentityService:
    """Enterprise SSO and Domain Discovery Service."""

    def discover_sso_by_domain(self, email: str) -> OrgSSODiscoveryResponse | None:
        domain = email.split("@")[-1].lower().strip() if "@" in email else ""
        for org_id, config in _in_memory_idp_configs.items():
            if domain in config.allowed_domains:
                return OrgSSODiscoveryResponse(
                    org_id=org_id,
                    org_name=f"Enterprise Org ({domain})",
                    sso_enforced=config.enforce_sso,
                    sso_type=config.sso_type,
                    login_url=f"https://auth.travelbrain.ai/api/v1/auth/{config.sso_type}/login?org_id={org_id}",
                )
        return None

    def get_idp_config(self, org_id: str) -> IdPConfigResponse | None:
        return _in_memory_idp_configs.get(org_id)

    def set_idp_config(self, req: IdPConfigRequest) -> IdPConfigResponse:
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
        _in_memory_idp_configs[req.org_id] = cfg
        logger.info(f"Updated IdP config for org '{req.org_id}'")
        return cfg

    def map_idp_groups_to_roles(self, org_id: str, idp_groups: list[str]) -> list[str]:
        config = self.get_idp_config(org_id)
        if not config or not config.group_role_mappings:
            return ["member"]
        assigned_roles = set()
        for grp in idp_groups:
            if grp in config.group_role_mappings:
                assigned_roles.add(config.group_role_mappings[grp])
        return list(assigned_roles) if assigned_roles else ["member"]


class SCIM2Service:
    """SCIM 2.0 Protocol User & Group Provisioning Service."""

    async def list_users(
        self, filter_query: str | None = None, start_index: int = 1, count: int = 100
    ) -> SCIMListResponse:
        users = list(_in_memory_scim_users.values())
        if filter_query and "userName eq" in filter_query:
            target_email = (
                filter_query.split("userName eq")[-1].replace('"', "").strip()
            )
            users = [u for u in users if u.userName.lower() == target_email.lower()]
        return SCIMListResponse(
            totalResults=len(users),
            startIndex=start_index,
            itemsPerPage=count,
            Resources=users[start_index - 1 : start_index - 1 + count],
        )

    async def create_user(self, user_data: SCIMUserSchema) -> SCIMUserSchema:
        user_id = generate_user_id(user_data.userName)
        now_str = datetime.now(UTC).isoformat()
        user_data.id = user_id
        user_data.meta = SCIMMeta(
            resourceType="User",
            created=now_str,
            lastModified=now_str,
            location=f"/scim/v2/Users/{user_id}",
        )
        _in_memory_scim_users[user_id] = user_data
        logger.info(f"SCIM Provisioned User '{user_data.userName}' ({user_id})")
        return user_data

    async def get_user(self, user_id: str) -> SCIMUserSchema | None:
        return _in_memory_scim_users.get(user_id)

    async def update_user(
        self, user_id: str, user_data: SCIMUserSchema
    ) -> SCIMUserSchema:
        user_data.id = user_id
        user_data.meta = SCIMMeta(
            resourceType="User",
            lastModified=datetime.now(UTC).isoformat(),
            location=f"/scim/v2/Users/{user_id}",
        )
        _in_memory_scim_users[user_id] = user_data
        return user_data

    async def delete_user(self, user_id: str) -> bool:
        if user_id in _in_memory_scim_users:
            del _in_memory_scim_users[user_id]
            logger.info(f"SCIM Deprovisioned User '{user_id}'")
            return True
        return False

    async def list_groups(self) -> SCIMListResponse:
        groups = list(_in_memory_scim_groups.values())
        return SCIMListResponse(
            totalResults=len(groups), startIndex=1, itemsPerPage=100, Resources=groups
        )

    async def create_group(self, group_data: SCIMGroupSchema) -> SCIMGroupSchema:
        grp_id = f"grp_{uuid.uuid4().hex[:12]}"
        now_str = datetime.now(UTC).isoformat()
        group_data.id = grp_id
        group_data.meta = SCIMMeta(
            resourceType="Group",
            created=now_str,
            lastModified=now_str,
            location=f"/scim/v2/Groups/{grp_id}",
        )
        _in_memory_scim_groups[grp_id] = group_data
        return group_data


enterprise_service = EnterpriseIdentityService()
scim_service = SCIM2Service()
