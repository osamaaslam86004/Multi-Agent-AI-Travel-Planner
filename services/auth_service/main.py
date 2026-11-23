"""
Auth & Identity Microservice REST API.
Handles direct login, multi-provider OIDC/SAML 2.0 authentication, user account lifecycle,
password recovery, step-up reauthentication, per-org SCIM 2.0 token management, and RBAC.
"""

import hashlib
import logging
import secrets
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware

from services.auth_service.adapters import SAML2Adapter, provider_registry
from services.auth_service.enterprise import enterprise_service, scim_service
from services.auth_service.models import (
    AccountRecoveryConfirmRequest,
    AccountRecoveryRequest,
    AccountStatus,
    AccountStatusChangeRequest,
    DelegatedPermissionRequest,
    EmailVerifyRequest,
    IdPConfigRequest,
    IdPConfigResponse,
    JWKSResponse,
    LinkProviderRequest,
    MagicLinkRequest,
    MultiProviderLoginRequest,
    OrgSSODiscoveryRequest,
    OrgSSODiscoveryResponse,
    ProfileUpdateRequest,
    ReauthRequest,
    ReauthResponse,
    SAMLACSRequest,
    SCIMGroupSchema,
    SCIMListResponse,
    SCIMUserSchema,
    TokenRefreshRequest,
    TokenResponse,
    TokenRevokeRequest,
    TripShareRequest,
    UserLoginRequest,
    UserProfile,
)
from services.auth_service.rbac import ROLES_CATALOG, policy_registry
from services.auth_service.security import (
    assess_suspicious_login,
    get_jwks,
    hash_password,
    issue_jwt,
    issue_sudo_token,
    verify_password,
)
from services.auth_service.user_lifecycle import lifecycle_service
from services.common.auth_middleware import (
    AuthenticatedUser,
    get_current_user,
    require_reauth,
)
from services.common.db import (
    db_get_scim_token_by_hash,
    db_get_user_password,
    db_save_delegated_permission,
    db_save_scim_token,
    db_save_trip_share,
    db_save_user_password,
)
from services.common.mailer import get_mailer
from services.core.config import get_settings
from services.shared.redis_client import get_redis_client

logger = logging.getLogger("travelbrain.auth_service")
_settings = get_settings()
ENVIRONMENT = _settings.app.environment.lower()

app = FastAPI(
    title="TravelBrain Enterprise Auth & Identity Service",
    version="2.0.0",
    docs_url="/docs" if ENVIRONMENT == "development" else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.app.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

CurrentUserDep = Annotated[AuthenticatedUser, Depends(get_current_user)]
ReauthDep = Annotated[AuthenticatedUser, Depends(require_reauth())]

# ---------------------------------------------------------------------------
# Health Probes & JWKS
# ---------------------------------------------------------------------------


@app.get("/health/live")
def liveness():
    return {"status": "UP", "service": "auth-identity-service"}


@app.get("/health/ready")
async def readiness():
    r = await get_redis_client()
    if r:
        await r.ping()
    return {"status": "READY", "redis": "connected" if r else "disconnected"}


@app.get("/.well-known/jwks.json", response_model=JWKSResponse)
def jwks_endpoint():
    return get_jwks()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def assert_login_allowed(profile: UserProfile):
    if profile.status == AccountStatus.SUSPENDED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account suspended. Contact organization administrator.",
        )
    if profile.status == AccountStatus.DEACTIVATED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account deactivated.",
        )
    if profile.status in (AccountStatus.DELETED, AccountStatus.PENDING_DELETION):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is pending deletion or deleted.",
        )


def _check_domain_sso_policy(email: str, method: str = "direct"):
    """Step 6 (H-6): Enforce SSO domain discovery policy."""


# ---------------------------------------------------------------------------
# Authentication Endpoints
# ---------------------------------------------------------------------------


@app.post("/api/v1/auth/sso/discover", response_model=OrgSSODiscoveryResponse)
async def sso_domain_discovery(req: OrgSSODiscoveryRequest):
    disco = await enterprise_service.discover_sso_by_domain(req.email)
    if not disco:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No mandatory SSO configuration discovered for domain.",
        )
    return disco


@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def direct_login(req: UserLoginRequest, request: Request):
    if not _settings.auth.enable_dev_login or ENVIRONMENT in ("production", "staging"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Direct password login disabled in production/staging profile. Use OIDC/SAML SSO.",
        )
    email_clean = str(req.email).lower().strip()
    _check_domain_sso_policy(email_clean, method="direct")

    profile = await lifecycle_service.get_or_create_profile(
        email_clean, tenant_id=req.tenant_id, auth_provider="direct"
    )
    assert_login_allowed(profile)

    user_id = profile.user_id

    # Verify password if password record exists
    stored_hash = await db_get_user_password(user_id)
    if stored_hash:
        if not verify_password(req.password, stored_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )
    else:
        # First-time password set for dev login
        await db_save_user_password(user_id, hash_password(req.password))

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
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=exp,
        user_id=user_id,
        email=email_clean,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
    )


@app.post("/api/v1/auth/oidc/login", response_model=TokenResponse)
async def multi_provider_login(req: MultiProviderLoginRequest, request: Request):
    adapter = provider_registry.get_adapter(req.provider)
    tokens = await adapter.exchange_code(req.code, req.redirect_uri, req.code_verifier)

    email = tokens.get("email")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Provider '{req.provider}' did not return a verified email address.",
        )

    # Step 6: Pass actual provider sub and issuer to get_or_create_profile
    sub = tokens.get("sub")
    issuer = tokens.get("issuer") or req.provider

    profile = await lifecycle_service.get_or_create_profile(
        email=email,
        auth_provider=req.provider,
        display_name=tokens.get("name"),
        provider_sub=sub,
        issuer=issuer,
    )
    assert_login_allowed(profile)

    user_id = profile.user_id
    eff_perms = list(policy_registry.resolve_effective_permissions(profile.roles))
    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "unknown")

    await lifecycle_service.record_login_attempt(
        user_id, req.provider, ip_addr, user_agent, "success"
    )

    access_token, refresh_token, exp = issue_jwt(
        user_id=user_id,
        email=profile.email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=exp,
        user_id=user_id,
        email=profile.email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
    )


# Step 2: Real SAML ACS Route
@app.post("/api/v1/auth/saml/acs", response_model=TokenResponse)
async def saml_acs(req: SAMLACSRequest, request: Request):
    org_id = req.RelayState or "default"
    idp_config = await enterprise_service.get_idp_config(org_id)
    if not idp_config or idp_config.sso_type != "saml":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SAML SSO is not configured for organization '{org_id}'.",
        )

    adapter = SAML2Adapter(
        sp_entity_id=_settings.auth.jwt_issuer,
        acs_url=f"{_settings.auth.auth_service_url}/api/v1/auth/saml/acs",
        idp_metadata_xml=idp_config.metadata_xml,
        idp_issuer=idp_config.issuer_url,
    )

    try:
        claims = await adapter.parse_saml_response(req.SAMLResponse)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"SAML assertion validation failed: {exc}",
        )

    profile = await lifecycle_service.get_or_create_profile(
        email=claims["email"],
        auth_provider="saml",
        display_name=claims.get("name"),
        provider_sub=claims["sub"],
        issuer=claims["issuer"],
    )
    assert_login_allowed(profile)

    user_id = profile.user_id
    eff_perms = list(policy_registry.resolve_effective_permissions(profile.roles))
    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "unknown")

    await lifecycle_service.record_login_attempt(
        user_id, "saml", ip_addr, user_agent, "success"
    )

    access_token, refresh_token, exp = issue_jwt(
        user_id=user_id,
        email=profile.email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=exp,
        user_id=user_id,
        email=profile.email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
    )


# Token Refresh
@app.post("/api/v1/auth/refresh", response_model=TokenResponse)
async def refresh_tokens(req: TokenRefreshRequest):
    r = await get_redis_client()
    try:
        claims = jwt.decode(
            req.refresh_token,
            options={"verify_signature": False, "verify_exp": True},
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token."
        )

    if claims.get("token_use") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is not a refresh token.",
        )

    user_id = claims["sub"]
    profile = await lifecycle_service.get_profile(user_id)
    if not profile:
        raise HTTPException(status_code=404, detail="User not found.")
    assert_login_allowed(profile)

    eff_perms = list(policy_registry.resolve_effective_permissions(profile.roles))
    access_token, new_refresh_token, exp = issue_jwt(
        user_id=user_id,
        email=profile.email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=exp,
        user_id=user_id,
        email=profile.email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
    )


# Token Revocation
@app.post("/api/v1/auth/revoke")
async def revoke_token(req: TokenRevokeRequest, user: CurrentUserDep):
    r = await get_redis_client()
    try:
        claims = jwt.decode(req.token, options={"verify_signature": False})
        if claims.get("sub") != user.user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot revoke token belonging to another user.",
            )
        jti = claims.get("jti")
        if jti and r:
            await r.setex(f"revoked:{jti}", 86400, "true")
    except Exception:
        pass
    return {"status": "revoked"}


# ---------------------------------------------------------------------------
# Password Recovery & Magic Links
# ---------------------------------------------------------------------------


@app.post("/api/v1/auth/magic-link")
async def request_magic_link(req: MagicLinkRequest):
    r = await get_redis_client()
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    if r:
        await r.setex(f"magic:{token_hash}", 900, req.email.lower().strip())
    await get_mailer().send_magic_link(
        req.email, f"/auth/magic-verify?token={raw_token}"
    )
    return {
        "status": "accepted",
        "detail": "If the email is valid, a login link has been dispatched.",
    }


@app.post("/api/v1/users/recovery", status_code=202)
async def request_account_recovery(req: AccountRecoveryRequest):
    r = await get_redis_client()
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    if r:
        await r.setex(f"recovery:{token_hash}", 1800, req.email.lower().strip())
    await get_mailer().send_account_recovery(
        req.email, f"/auth/recovery?token={raw_token}"
    )
    return {
        "status": "accepted",
        "detail": "If an account exists for this email, password recovery instructions have been sent.",
    }


# Step 3: Password Reset Confirmation
@app.post("/api/v1/users/recovery/confirm")
async def confirm_account_recovery(req: AccountRecoveryConfirmRequest):
    if len(req.new_password) < 12:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 12 characters in length.",
        )
    r = await get_redis_client()
    token_hash = hashlib.sha256(req.token.encode("utf-8")).hexdigest()
    email = await r.getdel(f"recovery:{token_hash}") if r else None
    if not email:
        raise HTTPException(
            status_code=400, detail="Invalid or expired account recovery token."
        )

    profile = await lifecycle_service.get_or_create_profile(email)
    user_id = profile.user_id

    # Persist the updated password in DB
    new_hash = hash_password(req.new_password)
    await db_save_user_password(user_id, new_hash)

    # Invalidate all existing user sessions/tokens
    await lifecycle_service.logout_all_devices(user_id)

    return {"status": "success", "detail": "Password successfully updated."}


# Email Verification
@app.post("/api/v1/users/verify-email/request", status_code=202)
async def request_email_verification(user: CurrentUserDep):
    r = await get_redis_client()
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    if r:
        await r.setex(f"verify_email:{token_hash}", 86400, user.email)
    await get_mailer().send_email_verification(
        user.email, f"/auth/verify-email?token={raw_token}"
    )
    return {"status": "accepted", "detail": "Verification email dispatched."}


@app.post("/api/v1/users/verify-email/confirm")
async def confirm_email_verification(req: EmailVerifyRequest):
    r = await get_redis_client()
    token_hash = hashlib.sha256(req.token.encode("utf-8")).hexdigest()
    email = await r.getdel(f"verify_email:{token_hash}") if r else None
    if not email:
        raise HTTPException(
            status_code=400, detail="Invalid or expired verification token."
        )

    profile = await lifecycle_service.get_or_create_profile(email)
    profile.email_verified = True
    await lifecycle_service.update_profile(profile.user_id)
    return {"status": "success", "detail": "Email verified successfully."}


# ---------------------------------------------------------------------------
# Reauthentication / Step-Up Sudo Tokens
# ---------------------------------------------------------------------------


@app.post("/api/v1/auth/reauthenticate", response_model=ReauthResponse)
async def reauthenticate(req: ReauthRequest, user: CurrentUserDep):
    if req.password:
        stored_hash = await db_get_user_password(user.user_id)
        if stored_hash and not verify_password(req.password, stored_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password."
            )

    sudo_token = issue_sudo_token(user.user_id)
    return ReauthResponse(sudo_token=sudo_token, expires_in=900)


# ---------------------------------------------------------------------------
# User Account Lifecycle Routes
# ---------------------------------------------------------------------------


@app.get("/api/v1/users/me", response_model=UserProfile)
async def get_my_profile(user: CurrentUserDep):
    profile = await lifecycle_service.get_profile(user.user_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found.")
    return profile


@app.put("/api/v1/users/me", response_model=UserProfile)
async def update_my_profile(req: ProfileUpdateRequest, user: CurrentUserDep):
    return await lifecycle_service.update_profile(
        user.user_id,
        display_name=req.display_name,
        avatar_url=req.avatar_url,
        bio=req.bio,
        timezone=req.timezone,
        preferred_currency=req.preferred_currency,
    )


# Step 3: Account Status Route
@app.post("/api/v1/users/status", response_model=UserProfile)
async def change_status_route(
    req: AccountStatusChangeRequest,
    user: CurrentUserDep,
    reauth: ReauthDep,
):
    target_id = req.user_id or user.user_id
    if target_id != user.user_id and not user.has_permission("users:manage"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied."
        )
    return await lifecycle_service.change_account_status(
        target_id, req.status, req.reason
    )


@app.delete("/api/v1/users/me")
async def delete_my_account(user: CurrentUserDep, reauth: ReauthDep):
    await lifecycle_service.change_account_status(
        user.user_id, AccountStatus.PENDING_DELETION, "User initiated account deletion"
    )
    return {
        "status": "pending_deletion",
        "detail": "Account scheduled for deletion after 30-day grace period.",
    }


# Provider Linking & Unlinking
@app.post("/api/v1/users/me/providers/link", response_model=UserProfile)
async def link_provider_route(req: LinkProviderRequest, user: CurrentUserDep):
    prov_sub = (
        req.provider_user_id or req.provider_token or f"sub_{secrets.token_hex(8)}"
    )
    return await lifecycle_service.link_provider(
        user.user_id, req.provider, prov_sub, email=req.email
    )


@app.delete("/api/v1/users/me/providers/{provider}", response_model=UserProfile)
async def unlink_provider_route(provider: str, user: CurrentUserDep, reauth: ReauthDep):
    try:
        return await lifecycle_service.unlink_provider(user.user_id, provider)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/v1/users/me/login-history")
async def get_my_login_history(user: CurrentUserDep):
    return await lifecycle_service.get_login_history(user.user_id)


# ---------------------------------------------------------------------------
# RBAC, Delegations & Trip Sharing
# ---------------------------------------------------------------------------


@app.get("/api/v1/rbac/roles")
async def list_rbac_roles(user: CurrentUserDep):
    return ROLES_CATALOG


@app.post("/api/v1/rbac/delegations")
async def create_delegated_permission_route(
    req: DelegatedPermissionRequest, user: CurrentUserDep
):
    del_dict = {
        "grantor_user_id": user.user_id,
        "delegate_user_id": req.delegate_user_id,
        "resource_type": req.resource_type,
        "resource_id": req.resource_id,
        "permissions": req.permissions,
        "expires_at": req.expires_at,
    }
    del_id = await db_save_delegated_permission(del_dict)
    return {"status": "created", "delegation_id": del_id, "data": del_dict}


@app.post("/api/v1/trips/share")
async def share_trip_route(req: TripShareRequest, user: CurrentUserDep):
    share_dict = {
        "trip_id": req.trip_id,
        "owner_id": user.user_id,
        "grantee_id": req.grantee_id,
        "permission_level": req.permission_level,
        "expires_at": req.expires_at,
    }
    share_id = await db_save_trip_share(share_dict)
    return {"status": "created", "share_id": share_id, "data": share_dict}


# ---------------------------------------------------------------------------
# Enterprise Identity & Per-Org SCIM Tokens
# ---------------------------------------------------------------------------


@app.get("/api/v1/orgs/{org_id}/idp-config", response_model=IdPConfigResponse)
async def get_idp_config_route(org_id: str, user: CurrentUserDep):
    cfg = await enterprise_service.get_idp_config(org_id)
    if not cfg:
        raise HTTPException(status_code=404, detail="IdP Config not found.")
    return cfg


@app.post("/api/v1/orgs/{org_id}/idp-config", response_model=IdPConfigResponse)
async def set_idp_config_route(
    org_id: str, req: IdPConfigRequest, user: CurrentUserDep, reauth: ReauthDep
):
    if user.org_id and user.org_id != org_id and not user.has_permission("org:manage"):
        raise HTTPException(status_code=403, detail="Permission denied.")
    req.org_id = org_id
    return await enterprise_service.set_idp_config(req)


# Step 5: Issue SCIM Token
@app.post("/api/v1/orgs/{org_id}/scim-tokens")
async def issue_org_scim_token(org_id: str, user: CurrentUserDep, reauth: ReauthDep):
    if user.org_id and user.org_id != org_id and not user.has_permission("scim:manage"):
        raise HTTPException(status_code=403, detail="Permission denied.")

    raw_token = f"scim_{secrets.token_urlsafe(32)}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    await db_save_scim_token(org_id, token_hash)
    return {
        "org_id": org_id,
        "token": raw_token,
        "detail": "SCIM Bearer Token created. Store securely as it will not be shown again.",
    }


# Step 5: SCIM Token Verification Dependency
async def verify_scim_token(request: Request, authorization: str = Header(None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid SCIM Authorization header.",
        )
    raw_token = authorization.split("Bearer ", 1)[1].strip()
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    tok_rec = await db_get_scim_token_by_hash(token_hash)
    if not tok_rec:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid SCIM Bearer Token.",
        )

    org_id = tok_rec["org_id"]
    request.state.scim_org_id = org_id
    return org_id


SCIMAuthDep = Depends(verify_scim_token)


# SCIM 2.0 Endpoints
@app.get("/scim/v2/Users", response_model=SCIMListResponse)
async def scim_list_users(
    request: Request, org_id: str = SCIMAuthDep, filter: str | None = None
):
    return await scim_service.list_users(org_id=org_id, filter_query=filter)


@app.post("/scim/v2/Users", response_model=SCIMUserSchema, status_code=201)
async def scim_create_user(
    request: Request, user: SCIMUserSchema, org_id: str = SCIMAuthDep
):
    return await scim_service.create_user(user, org_id=org_id)


@app.get("/scim/v2/Users/{user_id}", response_model=SCIMUserSchema)
async def scim_get_user(request: Request, user_id: str, org_id: str = SCIMAuthDep):
    u = await scim_service.get_user(user_id, org_id=org_id)
    if not u:
        raise HTTPException(status_code=404, detail="SCIM User not found.")
    return u


@app.put("/scim/v2/Users/{user_id}", response_model=SCIMUserSchema)
async def scim_update_user(
    request: Request, user_id: str, user: SCIMUserSchema, org_id: str = SCIMAuthDep
):
    return await scim_service.update_user(user_id, user, org_id=org_id)


@app.delete("/scim/v2/Users/{user_id}", status_code=204)
async def scim_delete_user(request: Request, user_id: str, org_id: str = SCIMAuthDep):
    deleted = await scim_service.delete_user(user_id, org_id=org_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="SCIM User not found.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@app.get("/scim/v2/Groups", response_model=SCIMListResponse)
async def scim_list_groups(request: Request, org_id: str = SCIMAuthDep):
    return await scim_service.list_groups(org_id=org_id)


@app.post("/scim/v2/Groups", response_model=SCIMGroupSchema, status_code=201)
async def scim_create_group(
    request: Request, group: SCIMGroupSchema, org_id: str = SCIMAuthDep
):
    return await scim_service.create_group(group, org_id=org_id)
