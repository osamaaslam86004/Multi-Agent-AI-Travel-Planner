"""
Authorization Architecture, Role-Based Access Control (RBAC), and Policy Registry.
Defines platform, organization, tenant, and resource-level roles, permission inheritance,
and trip resource access control.
"""

import logging

from services.auth_service.models import RoleDefinition

logger = logging.getLogger("travelbrain.auth.rbac")
# Standard Roles definition (Section 2.3)
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
    # Backward compatibility aliases
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
