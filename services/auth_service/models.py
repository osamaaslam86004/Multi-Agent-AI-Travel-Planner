"""
Pydantic models for Auth, User Account Lifecycle, Multi-Provider Auth, RBAC, and Enterprise Identity (SCIM/SSO).
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Core Auth & Token Models
# ---------------------------------------------------------------------------
class UserLoginRequest(BaseModel):
    email: str
    password: str
    tenant_id: str = "default"


class GoogleTokenExchangeRequest(BaseModel):
    code: str
    redirect_uri: str
    state: str
    code_verifier: str | None = None


class GoogleAuthUrlResponse(BaseModel):
    auth_url: str
    state: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"
    expires_in: int
    user_id: str
    email: str
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    tenant_id: str = "default"
    org_id: str | None = None
    mfa_verified: bool = True


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class TokenRevokeRequest(BaseModel):
    token: str


class JWKKey(BaseModel):
    kty: str = "RSA"
    use: str = "sig"
    alg: str = "RS256"
    kid: str
    n: str
    e: str


class JWKSResponse(BaseModel):
    keys: list[JWKKey]


# ---------------------------------------------------------------------------
# Section 2.1: User Account Lifecycle Models
# ---------------------------------------------------------------------------
class AccountStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"
    PENDING_DELETION = "pending_deletion"
    DELETED = "deleted"


class LinkedProviderInfo(BaseModel):
    provider: str
    provider_user_id: str
    email: str | None = None
    linked_at: str


class UserProfile(BaseModel):
    user_id: str
    email: str
    display_name: str | None = None
    avatar_url: str | None = None
    bio: str | None = None
    timezone: str = "UTC"
    preferred_currency: str = "USD"
    status: AccountStatus = AccountStatus.ACTIVE
    tenant_id: str = "default"
    org_id: str | None = None
    roles: list[str] = Field(default_factory=lambda: ["member"])
    email_verified: bool = False
    mfa_enabled: bool = False
    linked_providers: list[LinkedProviderInfo] = Field(default_factory=list)
    created_at: str
    updated_at: str


class ProfileUpdateRequest(BaseModel):
    display_name: str | None = Field(None, max_length=100)
    avatar_url: str | None = Field(None, max_length=500)
    bio: str | None = Field(None, max_length=500)
    timezone: str | None = Field(None, max_length=50)
    preferred_currency: str | None = Field(None, max_length=10)


class AccountStatusChangeRequest(BaseModel):
    status: AccountStatus
    reason: str | None = None


class AccountRecoveryRequest(BaseModel):
    email: str


class AccountRecoveryConfirmRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)


class LinkProviderRequest(BaseModel):
    provider: str
    provider_token: str


class LoginHistoryEntry(BaseModel):
    id: str
    user_id: str
    timestamp: str
    provider: str
    ip_address: str
    user_agent: str
    status: str  # success / failed
    suspicious: bool = False
    details: str | None = None


class ActiveSessionResponse(BaseModel):
    session_id: str
    user_id: str
    ip_address: str
    user_agent: str
    device_fingerprint: str | None = None
    is_trusted: bool = False
    created_at: str
    last_active_at: str
    expires_at: str
    is_current: bool = False


class RevokeSessionRequest(BaseModel):
    session_id: str


# ---------------------------------------------------------------------------
# Section 2.2: Authentication Enhancement Models
# ---------------------------------------------------------------------------
class MultiProviderLoginRequest(BaseModel):
    provider: str  # google, entra, github, generic_oidc
    code: str
    redirect_uri: str
    state: str
    code_verifier: str | None = None


class MagicLinkRequest(BaseModel):
    email: str


class MagicLinkVerifyRequest(BaseModel):
    token: str


class EmailVerifyRequest(BaseModel):
    token: str


class TOTPSetupResponse(BaseModel):
    secret: str
    otpauth_url: str
    qr_code_payload: str
    backup_codes: list[str]


class TOTPVerifyRequest(BaseModel):
    code: str


class MFAChallengeRequest(BaseModel):
    mfa_token: str
    code: str


class ReauthRequest(BaseModel):
    password: str | None = None
    mfa_code: str | None = None


class ReauthResponse(BaseModel):
    sudo_token: str
    expires_in: int = 900


class DeviceTrustRequest(BaseModel):
    device_fingerprint: str
    device_name: str | None = None
    trust_device: bool = True


# ---------------------------------------------------------------------------
# Section 2.3: Authorization Architecture (RBAC & Permissions)
# ---------------------------------------------------------------------------
class RoleDefinition(BaseModel):
    name: str
    scope: str  # platform, organization, tenant, resource
    description: str
    inherits: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)


class PermissionDefinition(BaseModel):
    name: str
    category: str
    description: str


class RoleAssignmentRequest(BaseModel):
    user_id: str
    role: str
    org_id: str | None = None
    tenant_id: str = "default"


class RoleRevocationRequest(BaseModel):
    user_id: str
    role: str
    org_id: str | None = None


class ResourcePermissionCheckRequest(BaseModel):
    resource_type: str  # trip, organization, tenant
    resource_id: str
    action: str  # read, write, delete, share, manage


class TripShareRequest(BaseModel):
    trip_id: str
    grantee_id: str
    permission_level: str  # read, write, admin
    expires_at: str | None = None


class DelegatedPermissionRequest(BaseModel):
    delegate_user_id: str
    resource_type: str
    resource_id: str
    permissions: list[str]
    expires_at: str


# ---------------------------------------------------------------------------
# Section 2.4: Enterprise Identity & SCIM 2.0 Models
# ---------------------------------------------------------------------------
class OrgSSODiscoveryRequest(BaseModel):
    email: str


class OrgSSODiscoveryResponse(BaseModel):
    org_id: str
    org_name: str
    sso_enforced: bool
    sso_type: str  # oidc, saml
    login_url: str


class IdPConfigRequest(BaseModel):
    org_id: str
    idp_name: str
    sso_type: str  # oidc, saml
    issuer_url: str
    client_id: str
    client_secret: str | None = None
    metadata_xml: str | None = None
    enforce_sso: bool = False
    allowed_domains: list[str] = Field(default_factory=list)
    group_role_mappings: dict[str, str] = Field(default_factory=dict)


class IdPConfigResponse(BaseModel):
    org_id: str
    idp_name: str
    sso_type: str
    issuer_url: str
    client_id: str
    enforce_sso: bool
    allowed_domains: list[str]
    group_role_mappings: dict[str, str]


class SAMLACSRequest(BaseModel):
    SAMLResponse: str
    RelayState: str | None = None


# SCIM 2.0 Standard Schemas
class SCIMName(BaseModel):
    formatted: str | None = None
    familyName: str | None = None
    givenName: str | None = None


class SCIMEmail(BaseModel):
    value: str
    type: str = "work"
    primary: bool = True


class SCIMMeta(BaseModel):
    resourceType: str
    created: str | None = None
    lastModified: str | None = None
    location: str | None = None


class SCIMUserSchema(BaseModel):
    schemas: list[str] = Field(
        default_factory=lambda: ["urn:ietf:params:scim:schemas:core:2.0:User"]
    )
    id: str | None = None
    externalId: str | None = None
    userName: str
    name: SCIMName | None = None
    displayName: str | None = None
    emails: list[SCIMEmail] = Field(default_factory=list)
    active: bool = True
    groups: list[dict[str, Any]] = Field(default_factory=list)
    meta: SCIMMeta | None = None


class SCIMMember(BaseModel):
    value: str
    display: str | None = None


class SCIMGroupSchema(BaseModel):
    schemas: list[str] = Field(
        default_factory=lambda: ["urn:ietf:params:scim:schemas:core:2.0:Group"]
    )
    id: str | None = None
    displayName: str
    members: list[SCIMMember] = Field(default_factory=list)
    meta: SCIMMeta | None = None


class SCIMListResponse(BaseModel):
    schemas: list[str] = Field(
        default_factory=lambda: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    )
    totalResults: int
    startIndex: int = 1
    itemsPerPage: int = 100
    Resources: list[Any] = Field(default_factory=list)


class SCIMPatchOperation(BaseModel):
    op: str  # add, replace, remove
    path: str | None = None
    value: Any = None
