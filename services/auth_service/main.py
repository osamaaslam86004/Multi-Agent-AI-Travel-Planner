"""
Auth & Enterprise Identity Microservice (Multi-Provider OIDC/SAML, Account Lifecycle, MFA, RBAC, SCIM 2.0).
"""

import logging
import secrets

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from services.auth_service.adapters import SAML2Adapter, provider_registry
from services.auth_service.enterprise import enterprise_service, scim_service
from services.auth_service.models import (
    AccountStatus,
    IdPConfigRequest,
    IdPConfigResponse,
    JWKSResponse,
    MagicLinkRequest,
    MagicLinkVerifyRequest,
    MultiProviderLoginRequest,
    OrgSSODiscoveryRequest,
    OrgSSODiscoveryResponse,
    ProfileUpdateRequest,
    ReauthRequest,
    ReauthResponse,
    ResourcePermissionCheckRequest,
    SAMLACSRequest,
    SCIMGroupSchema,
    SCIMListResponse,
    SCIMUserSchema,
    TokenResponse,
    TokenRevokeRequest,
    TOTPSetupResponse,
    TOTPVerifyRequest,
    UserLoginRequest,
)
from services.auth_service.rbac import policy_registry
from services.auth_service.security import (
    assess_suspicious_login,
    generate_totp_secret,
    get_jwks,
    get_totp_uri,
    issue_jwt,
    issue_magic_link_token,
    issue_sudo_token,
    verify_magic_link_token,
    verify_totp_code,
)
from services.auth_service.user_lifecycle import UserLifecycleService
from services.core.config import get_settings

logger = logging.getLogger("travelbrain.auth_service")
_settings = get_settings()
ENVIRONMENT = _settings.app.environment
REDIS_URL = _settings.redis.url

app = FastAPI(
    title="TravelBrain Auth & Enterprise Identity Service",
    version="2.0.0",
    description="OIDC, SAML 2.0, SCIM 2.0, MFA, Argon2id Identity & RBAC Provider",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

lifecycle_service = UserLifecycleService()


@app.get("/.well-known/jwks.json", response_model=JWKSResponse)
def jwks_endpoint():
    return get_jwks()


@app.get("/health/live")
def liveness():
    return {"status": "UP", "service": "auth-service"}


@app.get("/health/ready")
def readiness():
    return {"status": "READY", "keys_loaded": len(get_jwks()["keys"])}


@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def direct_login(req: UserLoginRequest, request: Request):
    if ENVIRONMENT == "production":
        raise HTTPException(
            status_code=403,
            detail="Direct password login disabled in production. Use OIDC SSO.",
        )
    email_clean = str(req.email).lower().strip()
    profile = await lifecycle_service.get_or_create_profile(
        email_clean, tenant_id=req.tenant_id, auth_provider="direct"
    )
    if profile.status != AccountStatus.ACTIVE:
        raise HTTPException(
            status_code=403, detail=f"Account is {profile.status.value}"
        )
    user_id = profile.user_id
    eff_perms = list(policy_registry.resolve_effective_permissions(profile.roles))
    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "unknown")
    suspicious, reason = assess_suspicious_login(
        user_id,
        ip_addr,
        user_agent,
        [h.model_dump() for h in await lifecycle_service.get_login_history(user_id)],
    )
    await lifecycle_service.record_login_attempt(
        user_id,
        "direct",
        ip_addr,
        user_agent,
        "success",
        suspicious=suspicious,
        details=reason,
    )
    access_token, refresh_token, exp = issue_jwt(
        user_id=user_id,
        email=email_clean,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=req.tenant_id,
        org_id=profile.org_id,
        mfa_verified=not profile.mfa_enabled,
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=exp,
        user_id=user_id,
        email=email_clean,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=req.tenant_id,
        org_id=profile.org_id,
        mfa_verified=not profile.mfa_enabled,
    )


@app.post("/api/v1/auth/oidc/login", response_model=TokenResponse)
async def multi_provider_login(req: MultiProviderLoginRequest, request: Request):
    adapter = provider_registry.get_adapter(req.provider)
    result = await adapter.exchange_code(req.code, req.redirect_uri, req.code_verifier)
    email = result.get("email", "")
    if not email:
        raise HTTPException(
            status_code=400, detail=f"Provider {req.provider} did not return email."
        )
    profile = await lifecycle_service.get_or_create_profile(
        email, auth_provider=req.provider, display_name=result.get("name")
    )
    if profile.status != AccountStatus.ACTIVE:
        raise HTTPException(
            status_code=403, detail=f"Account is {profile.status.value}"
        )
    eff_perms = list(policy_registry.resolve_effective_permissions(profile.roles))
    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "unknown")
    await lifecycle_service.record_login_attempt(
        profile.user_id, req.provider, ip_addr, user_agent, "success"
    )
    access_token, refresh_token, exp = issue_jwt(
        user_id=profile.user_id,
        email=email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
        email_verified=True,
        mfa_verified=True,
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=exp,
        user_id=profile.user_id,
        email=email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
        mfa_verified=True,
    )


@app.post("/api/v1/auth/magic-link")
async def request_magic_link(req: MagicLinkRequest):
    token = issue_magic_link_token(req.email)
    return {
        "status": "sent",
        "magic_link_url": f"https://auth.travelbrain.ai/magic?token={token}",
    }


@app.post("/api/v1/auth/magic-link/verify", response_model=TokenResponse)
async def verify_magic_link(req: MagicLinkVerifyRequest, request: Request):
    email = verify_magic_link_token(req.token)
    if not email:
        raise HTTPException(
            status_code=400, detail="Invalid or expired magic link token."
        )
    profile = await lifecycle_service.get_or_create_profile(
        email, auth_provider="magic_link"
    )
    eff_perms = list(policy_registry.resolve_effective_permissions(profile.roles))
    access_token, refresh_token, exp = issue_jwt(
        user_id=profile.user_id,
        email=email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
        email_verified=True,
        mfa_verified=True,
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=exp,
        user_id=profile.user_id,
        email=email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
        mfa_verified=True,
    )


@app.post("/api/v1/auth/mfa/setup", response_model=TOTPSetupResponse)
async def setup_mfa(user_id: str, email: str):
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, email)
    backup_codes = [secrets.token_hex(4) for _ in range(8)]
    return TOTPSetupResponse(
        secret=secret, otpauth_url=uri, qr_code_payload=uri, backup_codes=backup_codes
    )


@app.post("/api/v1/auth/mfa/verify")
async def verify_mfa(req: TOTPVerifyRequest, secret: str):
    if not verify_totp_code(secret, req.code):
        raise HTTPException(status_code=400, detail="Invalid TOTP verification code.")
    return {"status": "mfa_verified"}


@app.post("/api/v1/auth/reauthenticate", response_model=ReauthResponse)
async def reauthenticate(req: ReauthRequest, user_id: str):
    sudo_token = issue_sudo_token(user_id)
    return ReauthResponse(sudo_token=sudo_token, expires_in=900)


@app.get("/api/v1/users/me")
async def get_my_profile(user_id: str):
    p = await lifecycle_service.get_profile(user_id)
    if not p:
        raise HTTPException(status_code=404, detail="User profile not found.")
    return p


@app.put("/api/v1/users/me")
async def update_my_profile(user_id: str, req: ProfileUpdateRequest):
    return await lifecycle_service.update_profile(
        user_id, **req.model_dump(exclude_unset=True)
    )


@app.get("/api/v1/users/me/sessions")
async def list_my_sessions(user_id: str, session_id: str | None = None):
    return await lifecycle_service.list_active_sessions(user_id, session_id)


@app.delete("/api/v1/users/me/sessions/{session_id}")
async def revoke_my_session(user_id: str, session_id: str):
    await lifecycle_service.revoke_session(user_id, session_id)
    return {"status": "revoked", "session_id": session_id}


@app.post("/api/v1/users/me/logout-all")
async def logout_all_my_devices(user_id: str):
    count = await lifecycle_service.logout_all_devices(user_id)
    return {"status": "logged_out_all", "revoked_sessions_count": count}


@app.get("/api/v1/users/me/login-history")
async def get_my_login_history(user_id: str):
    return await lifecycle_service.get_login_history(user_id)


@app.get("/api/v1/rbac/roles")
def list_rbac_roles():
    return list(policy_registry.roles.values())


@app.post("/api/v1/rbac/check-permission")
def check_rbac_permission(
    req: ResourcePermissionCheckRequest,
    user_roles: list[str],
    user_id: str,
    owner_id: str,
):
    allowed = policy_registry.can_access_trip(
        user_id, user_roles, owner_id, required_action=req.action
    )
    return {"allowed": allowed, "resource_id": req.resource_id, "action": req.action}


@app.post("/api/v1/auth/sso/discover", response_model=OrgSSODiscoveryResponse)
def discover_sso(req: OrgSSODiscoveryRequest):
    res = enterprise_service.discover_sso_by_domain(req.email)
    if not res:
        raise HTTPException(
            status_code=404, detail="No enterprise SSO configured for domain."
        )
    return res


@app.post("/api/v1/auth/saml/acs")
async def saml_acs(req: SAMLACSRequest):
    adapter = SAML2Adapter("sp_id", "acs_url")
    res = await adapter.parse_saml_response(req.SAMLResponse)
    profile = await lifecycle_service.get_or_create_profile(
        res["email"], auth_provider="saml"
    )
    eff_perms = list(policy_registry.resolve_effective_permissions(profile.roles))
    access_token, refresh_token, exp = issue_jwt(
        user_id=profile.user_id,
        email=res["email"],
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
        email_verified=True,
        mfa_verified=True,
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=exp,
        user_id=profile.user_id,
        email=res["email"],
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
        mfa_verified=True,
    )


@app.get("/api/v1/orgs/{org_id}/idp-config", response_model=IdPConfigResponse)
def get_idp_configuration(org_id: str):
    cfg = enterprise_service.get_idp_config(org_id)
    if not cfg:
        raise HTTPException(
            status_code=404, detail=f"IdP configuration not found for org {org_id}"
        )
    return cfg


@app.post("/api/v1/orgs/{org_id}/idp-config", response_model=IdPConfigResponse)
def update_idp_configuration(org_id: str, req: IdPConfigRequest):
    req.org_id = org_id
    return enterprise_service.set_idp_config(req)


# SCIM 2.0 Standard Provisioning Endpoints
@app.get("/scim/v2/Users", response_model=SCIMListResponse)
async def scim_list_users(
    filter: str | None = None, startIndex: int = 1, count: int = 100
):
    return await scim_service.list_users(filter, startIndex, count)


@app.post("/scim/v2/Users", response_model=SCIMUserSchema, status_code=201)
async def scim_create_user(user: SCIMUserSchema):
    return await scim_service.create_user(user)


@app.get("/scim/v2/Users/{user_id}", response_model=SCIMUserSchema)
async def scim_get_user(user_id: str):
    u = await scim_service.get_user(user_id)
    if not u:
        raise HTTPException(status_code=404, detail="SCIM User not found")
    return u


@app.delete("/scim/v2/Users/{user_id}", status_code=204)
async def scim_delete_user(user_id: str):
    await scim_service.delete_user(user_id)
    return Response(status_code=204)


@app.get("/scim/v2/Groups", response_model=SCIMListResponse)
async def scim_list_groups():
    return await scim_service.list_groups()


@app.post("/scim/v2/Groups", response_model=SCIMGroupSchema, status_code=201)
async def scim_create_group(group: SCIMGroupSchema):
    return await scim_service.create_group(group)


@app.post("/api/v1/auth/revoke")
async def revoke_token(req: TokenRevokeRequest):
    return {"status": "revoked"}
