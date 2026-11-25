"""
Authorization Architecture, Role-Based Access Control (RBAC), and Policy Registry.
Defines platform, organization, tenant, and resource-level roles, permission inheritance,
role rank hierarchy, escalation ceiling checks, and trip resource access control.
"""

import logging

from fastapi import HTTPException, status

from services.auth_service.models import RoleDefinition

logger = logging.getLogger("travelbrain.auth.rbac")
ROLES_CATALOG: dict[str, RoleDefinition] = {
    "platform_owner": RoleDefinition(
        name="Platform Owner",
        scope="platform",
        description="Full platform super-admin access",
        permissions=["*"],
    ),
    "platform_administrator": RoleDefinition(
        name="Platform Administrator",
        scope="platform",
        description="Platform operational administration",
        permissions=[
            "platform:admin",
            "org:manage",
            "users:manage",
            "trips:manage",
            "audit:read",
        ],
    ),
    "organization_owner": RoleDefinition(
        name="Organization Owner",
        scope="organization",
        description="Full organization administration & billing",
        inherits=["organization_administrator"],
        permissions=["org:owner", "sso:manage", "scim:manage"],
    ),
    "organization_administrator": RoleDefinition(
        name="Organization Administrator",
        scope="organization",
        description="Organization management & user assignment",
        inherits=["travel_manager"],
        permissions=[
            "org:manage",
            "users:manage",
            "sso:read",
            "scim:read",
            "audit:read",
        ],
    ),
    "travel_manager": RoleDefinition(
        name="Travel Manager",
        scope="organization",
        description="Managed travelers & corporate travel policy",
        inherits=["travel_planner"],
        permissions=["trips:manage", "trips:assign", "users:read"],
    ),
    "travel_planner": RoleDefinition(
        name="Travel Planner",
        scope="organization",
        description="Create and manage assigned trips",
        inherits=["member"],
        permissions=[
            "trips:create",
            "trips:edit",
            "trips:read",
            "trips:share",
            "trips:delete",
        ],
    ),
    "member": RoleDefinition(
        name="Member",
        scope="tenant",
        description="Personal trip planner & member resources",
        permissions=[
            "trips:create_own",
            "trips:read_own",
            "trips:edit_own",
            "trips:delete_own",
        ],
    ),
    "viewer": RoleDefinition(
        name="Viewer",
        scope="resource",
        description="Read-only access to shared resources",
        permissions=["trips:read_shared"],
    ),
    "traveler": RoleDefinition(
        name="Traveler",
        scope="tenant",
        description="Default user role",
        permissions=["trips:create_own", "trips:read_own"],
    ),
    "admin": RoleDefinition(
        name="Admin",
        scope="platform",
        description="Legacy admin role",
        permissions=["platform:admin", "trips:manage"],
    ),
    "google_verified": RoleDefinition(
        name="Google Verified",
        scope="tenant",
        description="OIDC verified identity",
        permissions=[],
    ),
}
ROLE_RANKS: dict[str, int] = {
    "platform_owner": 100,
    "platform_administrator": 80,
    "admin": 80,
    "organization_owner": 70,
    "organization_administrator": 60,
    "travel_manager": 50,
    "travel_planner": 40,
    "member": 20,
    "traveler": 20,
    "viewer": 10,
    "google_verified": 10,
}


def get_role_rank(role_name: str) -> int:
    r_clean = role_name.lower().strip().replace(" ", "_")
    return ROLE_RANKS.get(r_clean, 0)


def get_max_caller_rank(caller_roles: list[str]) -> int:
    if not caller_roles:
        return 0
    return max([get_role_rank(r) for r in caller_roles])


def validate_role_assignment(
    caller_roles: list[str],
    target_role: str,
    caller_org_id: str | None = None,
    target_org_id: str | None = None,
) -> None:
    """
    Enforces role catalog, role scope, caller scope, target rank, and escalation ceiling.
    Raises HTTPException(400) if role invalid, or HTTPException(403) if authorization check fails.
    """
    r_clean = target_role.lower().strip().replace(" ", "_")
    if r_clean not in ROLES_CATALOG:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Role '{target_role}' does not exist in the role catalog.",
        )
    caller_max_rank = get_max_caller_rank(caller_roles)
    target_rank = get_role_rank(r_clean)
    # Escalation ceiling check
    if caller_max_rank < target_rank:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Privilege escalation blocked: caller rank ({caller_max_rank}) is lower than target role rank ({target_rank}).",
        )
    role_def = ROLES_CATALOG[r_clean]
    # Scope check
    if role_def.scope == "platform":
        is_platform_admin = any(
            r.lower() in ("platform_owner", "platform_administrator", "admin")
            for r in caller_roles
        )
        if not is_platform_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Assigning platform-scoped roles requires platform administrator privileges.",
            )
    elif role_def.scope == "organization":
        is_org_admin = any(
            r.lower()
            in (
                "platform_owner",
                "platform_administrator",
                "admin",
                "organization_owner",
                "organization_administrator",
            )
            for r in caller_roles
        )
        if not is_org_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Assigning organization-scoped roles requires organization administrator privileges.",
            )
        if caller_org_id and target_org_id and caller_org_id != target_org_id:
            is_platform_admin = any(
                r.lower() in ("platform_owner", "platform_administrator", "admin")
                for r in caller_roles
            )
            if not is_platform_admin:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Cross-organization role assignment is prohibited.",
                )


class AuthorizationPolicyRegistry:
    """Policy engine for role hierarchy, permission expansion, and resource access evaluation."""

    def __init__(self):
        self.roles = ROLES_CATALOG

    def resolve_effective_permissions(self, user_roles: list[str]) -> set[str]:
        effective: set[str] = set()
        visited: set[str] = set()

        def _expand(role_key: str):
            r_clean = role_key.lower().strip().replace(" ", "_")
            if r_clean in visited:
                return
            visited.add(r_clean)
            role_def = self.roles.get(r_clean)
            if not role_def:
                return
            effective.update(role_def.permissions)
            for parent in role_def.inherits:
                _expand(parent)

        for r in user_roles:
            _expand(r)
        return effective

    def has_permission(self, user_roles: list[str], required_permission: str) -> bool:
        effective = self.resolve_effective_permissions(user_roles)
        if "*" in effective:
            return True
        if required_permission in effective:
            return True
        domain_prefix = required_permission.split(":")[0]
        return f"{domain_prefix}:*" in effective

    def can_access_trip(
        self,
        user_id: str,
        user_roles: list[str],
        trip_owner_id: str,
        shared_permissions: dict[str, str] | None = None,
        required_action: str = "read",
    ) -> bool:
        if self.has_permission(user_roles, "*") or self.has_permission(
            user_roles, "trips:manage"
        ):
            return True
        if user_id == trip_owner_id:
            return True
        if shared_permissions and user_id in shared_permissions:
            perm_level = shared_permissions[user_id]
            if required_action == "read":
                return perm_level in ["read", "write", "admin"]
            elif required_action in ["write", "edit"]:
                return perm_level in ["write", "admin"]
            elif required_action == "admin":
                return perm_level == "admin"
        return False


policy_registry = AuthorizationPolicyRegistry()
