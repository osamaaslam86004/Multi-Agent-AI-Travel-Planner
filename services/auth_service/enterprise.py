"""
Enterprise Identity, SSO Domain Discovery, SAML 2.0, and SCIM 2.0 Provisioning Engine with DB Persistence.
Supports RFC 7644 SCIM filtering, PATCH path grammar, ETags, pagination/sorting, and Group-to-Role reconciliation.
"""

import base64
import hashlib
import json
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
    SCIMPatchOperation,
    SCIMUserSchema,
)
from services.auth_service.security import generate_user_id
from services.common.db import (
    db_assign_role,
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
        if value.startswith("enc:v1:"):
            return value
        return "enc:v1:" + self._secret_cipher().encrypt(value.encode()).decode()

    def _decrypt_client_secret(self, value: str | None) -> str | None:
        if not value:
            return value
        if value.startswith("enc:v1:"):
            return self._secret_cipher().decrypt(value[7:].encode()).decode()
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


# Helper functions for SCIM 2.0 RFC 7644 filter evaluation and patch grammar
def _get_nested_attr(obj: Any, path: str) -> Any:
    if not path or not obj:
        return None
    if "[" in path and "]" in path:
        attr_name = path[: path.index("[")]
        sub_filter = path[path.index("[") + 1 : path.index("]")]
        rest = path[path.index("]") + 1 :].lstrip(".")
        items = (
            obj.get(attr_name, [])
            if isinstance(obj, dict)
            else getattr(obj, attr_name, [])
        )
        if isinstance(items, list):
            matched = [
                item
                for item in items
                if evaluate_scim_filter(
                    item if isinstance(item, dict) else item.model_dump(), sub_filter
                )
            ]
            if rest:
                res = []
                for item in matched:
                    v = _get_nested_attr(item, rest)
                    if v is not None:
                        res.append(v)
                return res
            return matched
        return None
    parts = path.split(".")
    curr = obj
    for p in parts:
        if isinstance(curr, dict):
            curr = curr.get(p)
        elif hasattr(curr, p):
            curr = getattr(curr, p)
        else:
            return None
    return curr


def evaluate_scim_filter(resource_dict: dict, filter_query: str) -> bool:
    if not filter_query or not filter_query.strip():
        return True
    q = filter_query.strip()
    if " and " in q:
        parts = q.split(" and ")
        return all(evaluate_scim_filter(resource_dict, p) for p in parts)
    if " or " in q:
        parts = q.split(" or ")
        return any(evaluate_scim_filter(resource_dict, p) for p in parts)
    if q.lower().startswith("not "):
        return not evaluate_scim_filter(resource_dict, q[4:])

    tokens = q.split(None, 2)
    if len(tokens) == 2 and tokens[1].lower() == "pr":
        val = _get_nested_attr(resource_dict, tokens[0])
        return val is not None and val != "" and val != []
    if len(tokens) < 3:
        return True
    attr_path, op, target_val = tokens[0], tokens[1].lower(), tokens[2].strip("\"'")
    val = _get_nested_attr(resource_dict, attr_path)
    if isinstance(val, list):
        if op == "eq":
            return target_val in [str(x) for x in val]
        return len(val) > 0
    if val is None:
        return op == "ne"

    s_val = str(val).lower()
    t_val = str(target_val).lower()
    if op == "eq":
        return s_val == t_val
    elif op == "ne":
        return s_val != t_val
    elif op == "co":
        return t_val in s_val
    elif op == "sw":
        return s_val.startswith(t_val)
    elif op == "ew":
        return s_val.endswith(t_val)
    elif op == "gt":
        return val > target_val
    elif op == "ge":
        return val >= target_val
    elif op == "lt":
        return val < target_val
    elif op == "le":
        return val <= target_val
    return True


def apply_scim_patch(resource_dict: dict, operations: list[SCIMPatchOperation]) -> dict:
    updated = json.loads(json.dumps(resource_dict))
    for op in operations:
        op_type = op.op.lower()
        path = op.path
        val = op.value
        if not path:
            if isinstance(val, dict):
                updated.update(val)
            continue
        if "[" in path and "]" in path:
            attr_name = path[: path.index("[")]
            sub_filter = path[path.index("[") + 1 : path.index("]")]
            rest = path[path.index("]") + 1 :].lstrip(".")
            list_items = updated.get(attr_name, [])
            if op_type in ("add", "replace"):
                for item in list_items:
                    if evaluate_scim_filter(item, sub_filter):
                        if rest:
                            item[rest] = val
                        elif isinstance(val, dict):
                            item.update(val)
            elif op_type == "remove":
                updated[attr_name] = [
                    item
                    for item in list_items
                    if not evaluate_scim_filter(item, sub_filter)
                ]
        else:
            parts = path.split(".")
            curr = updated
            for p in parts[:-1]:
                if p not in curr or not isinstance(curr[p], dict):
                    curr[p] = {}
                curr = curr[p]
            last_part = parts[-1]
            if op_type in ("add", "replace"):
                curr[last_part] = val
            elif op_type == "remove":
                curr.pop(last_part, None)
    return updated


def calculate_scim_version(resource_dict: dict) -> str:
    serialized = json.dumps(resource_dict, sort_keys=True)
    h = hashlib.md5(serialized.encode("utf-8")).hexdigest()
    return f'W/"{h}"'


class SCIM2Service:
    """SCIM 2.0 Protocol User & Group Provisioning Service with DB Persistence and Group-to-Role Reconciliation."""

    async def list_users(
        self,
        org_id: str | None = None,
        filter_query: str | None = None,
        start_index: int = 1,
        count: int = 100,
        sort_by: str | None = None,
        sort_order: str = "ascending",
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

        if filter_query:
            user_objects = [
                u
                for u in user_objects
                if evaluate_scim_filter(u.model_dump(), filter_query)
            ]

        if sort_by:
            rev = sort_order.lower() == "descending"
            user_objects.sort(
                key=lambda u: str(_get_nested_attr(u.model_dump(), sort_by) or ""),
                reverse=rev,
            )

        total_results = len(user_objects)
        idx = max(0, start_index - 1)
        cnt = max(0, count)
        paged = user_objects[idx : idx + cnt]

        for u in paged:
            u_dict = u.model_dump()
            ver = calculate_scim_version(u_dict)
            if u.meta:
                u.meta.version = ver

        return SCIMListResponse(
            totalResults=total_results,
            startIndex=start_index,
            itemsPerPage=len(paged),
            Resources=paged,
        )

    async def create_user(
        self, user_data: SCIMUserSchema, org_id: str | None = None
    ) -> SCIMUserSchema:
        user_id = generate_user_id(user_data.userName)
        now_str = datetime.now(UTC).isoformat()
        user_data.id = user_id
        ver = calculate_scim_version(user_data.model_dump())
        user_data.meta = SCIMMeta(
            resourceType="User",
            created=now_str,
            lastModified=now_str,
            location=f"/scim/v2/Users/{user_id}",
            version=ver,
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
            u = SCIMUserSchema(**u_dict)
            if u.meta:
                u.meta.version = calculate_scim_version(u_dict)
            return u
        u = _in_memory_scim_users.get(f"{org_id or 'default'}:{user_id}")
        if u and u.meta:
            u.meta.version = calculate_scim_version(u.model_dump())
        return u

    async def update_user(
        self,
        user_id: str,
        user_data: SCIMUserSchema,
        org_id: str | None = None,
        if_match: str | None = None,
    ) -> SCIMUserSchema:
        existing = await self.get_user(user_id, org_id=org_id)
        if if_match and existing and existing.meta and existing.meta.version:
            if if_match.strip() != existing.meta.version.strip():
                raise ValueError("SCIM ETag version mismatch (If-Match failure)")

        user_data.id = user_id
        now_str = datetime.now(UTC).isoformat()
        ver = calculate_scim_version(user_data.model_dump())
        user_data.meta = SCIMMeta(
            resourceType="User",
            lastModified=now_str,
            location=f"/scim/v2/Users/{user_id}",
            version=ver,
        )
        await db_save_scim_user(user_data.model_dump(), org_id=org_id)
        _in_memory_scim_users[f"{org_id or 'default'}:{user_id}"] = user_data
        await self._sync_internal_user_status(
            user_data.userName, user_data.active, org_id
        )
        return user_data

    async def patch_user(
        self,
        user_id: str,
        operations: list[SCIMPatchOperation],
        org_id: str | None = None,
        if_match: str | None = None,
    ) -> SCIMUserSchema:
        existing = await self.get_user(user_id, org_id=org_id)
        if not existing:
            raise ValueError("SCIM user not found")
        if if_match and existing.meta and existing.meta.version:
            if if_match.strip() != existing.meta.version.strip():
                raise ValueError("SCIM ETag version mismatch (If-Match failure)")

        u_dict = existing.model_dump()
        patched_dict = apply_scim_patch(u_dict, operations)
        updated_user = SCIMUserSchema(**patched_dict)
        return await self.update_user(user_id, updated_user, org_id=org_id)

    async def delete_user(
        self, user_id: str, org_id: str | None = None, if_match: str | None = None
    ) -> bool:
        existing = await self.get_user(user_id, org_id=org_id)
        if not existing:
            return False
        if if_match and existing.meta and existing.meta.version:
            if if_match.strip() != existing.meta.version.strip():
                raise ValueError("SCIM ETag version mismatch (If-Match failure)")

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

    async def list_groups(
        self,
        org_id: str | None = None,
        filter_query: str | None = None,
        start_index: int = 1,
        count: int = 100,
        sort_by: str | None = None,
        sort_order: str = "ascending",
    ) -> SCIMListResponse:
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

        if filter_query:
            grp_objects = [
                g
                for g in grp_objects
                if evaluate_scim_filter(g.model_dump(), filter_query)
            ]

        if sort_by:
            rev = sort_order.lower() == "descending"
            grp_objects.sort(
                key=lambda g: str(_get_nested_attr(g.model_dump(), sort_by) or ""),
                reverse=rev,
            )

        total = len(grp_objects)
        idx = max(0, start_index - 1)
        cnt = max(0, count)
        paged = grp_objects[idx : idx + cnt]

        for g in paged:
            g_dict = g.model_dump()
            ver = calculate_scim_version(g_dict)
            if g.meta:
                g.meta.version = ver

        return SCIMListResponse(
            totalResults=total,
            startIndex=start_index,
            itemsPerPage=len(paged),
            Resources=paged,
        )

    async def create_group(
        self, group_data: SCIMGroupSchema, org_id: str | None = None
    ) -> SCIMGroupSchema:
        grp_id = f"grp_{uuid.uuid4().hex[:12]}"
        now_str = datetime.now(UTC).isoformat()
        group_data.id = grp_id
        ver = calculate_scim_version(group_data.model_dump())
        group_data.meta = SCIMMeta(
            resourceType="Group",
            created=now_str,
            lastModified=now_str,
            location=f"/scim/v2/Groups/{grp_id}",
            version=ver,
        )
        await db_save_scim_group(group_data.model_dump(), org_id=org_id)
        _in_memory_scim_groups[f"{org_id or 'default'}:{grp_id}"] = group_data
        await self.reconcile_group_roles(group_data, org_id)
        return group_data

    async def update_group(
        self,
        group_id: str,
        group_data: SCIMGroupSchema,
        org_id: str | None = None,
        if_match: str | None = None,
    ) -> SCIMGroupSchema:
        current = await self.get_group(group_id, org_id=org_id)
        if not current:
            raise ValueError("SCIM group not found")
        if if_match and current.meta and current.meta.version:
            if if_match.strip() != current.meta.version.strip():
                raise ValueError("SCIM ETag version mismatch (If-Match failure)")

        group_data.id = group_id
        now_str = datetime.now(UTC).isoformat()
        ver = calculate_scim_version(group_data.model_dump())
        group_data.meta = SCIMMeta(
            resourceType="Group",
            lastModified=now_str,
            location=f"/scim/v2/Groups/{group_id}",
            version=ver,
        )
        await db_save_scim_group(group_data.model_dump(), org_id=org_id)
        _in_memory_scim_groups[f"{org_id or 'default'}:{group_id}"] = group_data
        await self.reconcile_group_roles(group_data, org_id)
        return group_data

    async def patch_group(
        self,
        group_id: str,
        operations: list[SCIMPatchOperation],
        org_id: str | None = None,
        if_match: str | None = None,
    ) -> SCIMGroupSchema:
        existing = await self.get_group(group_id, org_id=org_id)
        if not existing:
            raise ValueError("SCIM group not found")
        if if_match and existing.meta and existing.meta.version:
            if if_match.strip() != existing.meta.version.strip():
                raise ValueError("SCIM ETag version mismatch (If-Match failure)")

        g_dict = existing.model_dump()
        patched_dict = apply_scim_patch(g_dict, operations)
        updated_group = SCIMGroupSchema(**patched_dict)
        return await self.update_group(group_id, updated_group, org_id=org_id)

    async def get_group(
        self, group_id: str, org_id: str | None = None
    ) -> SCIMGroupSchema | None:
        g_dict = await db_get_scim_group(group_id, org_id=org_id)
        if g_dict:
            g = SCIMGroupSchema(**g_dict)
            if g.meta:
                g.meta.version = calculate_scim_version(g_dict)
            return g
        g = _in_memory_scim_groups.get(f"{org_id or 'default'}:{group_id}")
        if g and g.meta:
            g.meta.version = calculate_scim_version(g.model_dump())
        return g

    async def delete_group(
        self, group_id: str, org_id: str | None = None, if_match: str | None = None
    ) -> bool:
        existing = await self.get_group(group_id, org_id=org_id)
        if not existing:
            return False
        if if_match and existing.meta and existing.meta.version:
            if if_match.strip() != existing.meta.version.strip():
                raise ValueError("SCIM ETag version mismatch (If-Match failure)")

        success = await db_delete_scim_group(group_id, org_id=org_id)
        _in_memory_scim_groups.pop(f"{org_id or 'default'}:{group_id}", None)
        return success

    async def reconcile_group_roles(
        self, group: SCIMGroupSchema, org_id: str | None
    ) -> None:
        if not org_id:
            return
        config = await enterprise_service.get_idp_config(org_id)
        if not config or not config.group_role_mappings:
            return
        mapped_role = config.group_role_mappings.get(group.displayName)
        if not mapped_role:
            return
        from services.auth_service.user_lifecycle import lifecycle_service
        from services.common.db import db_upsert_user_profile

        for member in group.members:
            scim_user = await self.get_user(member.value, org_id=org_id)
            if scim_user and scim_user.userName:
                profile = await lifecycle_service.get_or_create_profile(
                    scim_user.userName
                )
                if profile and mapped_role not in profile.roles:
                    profile.roles.append(mapped_role)
                    await db_upsert_user_profile(profile.model_dump())
                    await db_assign_role(
                        profile.user_id,
                        mapped_role,
                        "organization",
                        org_id,
                        "scim_group_reconciliation",
                    )
                    await lifecycle_service.logout_all_devices(profile.user_id)


enterprise_service = EnterpriseIdentityService()
scim_service = SCIM2Service()
