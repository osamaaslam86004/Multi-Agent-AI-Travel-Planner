"""
Auth & Enterprise Identity Microservice.
Multi-Provider OIDC/SAML 2.0, Account Lifecycle, MFA, RBAC, SCIM 2.0, Refresh Token Rotation,
and Central Login Policy Gate.
"""

import logging
import secrets

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware

from services.auth_service.adapters import SAML2Adapter, provider_registry
from services.auth_service.enterprise import (
    enterprise_service,
    scim_service,
    verify_scim_token,
)
from services.auth_service.models import (
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
    TokenRefreshRequest,
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
from services.auth_service.user_lifecycle import (
    UserLifecycleService,
    assert_login_allowed,
)
from services.common.auth_middleware import (
    CurrentUserDep,
)
from services.core.config import get_settings
from services.shared.redis_client import get_redis_client

logger = logging.getLogger("travelbrain.auth_service")
_settings = get_settings()
ENVIRONMENT = _settings.app.environment.lower()

app = FastAPI(
    title="TravelBrain Auth & Enterprise Identity Service",
    version="2.0.0",
    description="OIDC, SAML 2.0, SCIM 2.0, MFA, Argon2id Identity, RBAC & Revocation Provider",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.security.cors_origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

lifecycle_service = UserLifecycleService()


def _check_domain_sso_policy(email: str, login_method: str = "direct") -> None:
    """Step 6 (H-6): Central login policy gate ensuring SSO-enforced domains reject direct login."""
    sso_disc = enterprise_service.discover_sso_by_domain(email)
    if (
        sso_disc
        and sso_disc.sso_enforced
        and login_method not in (sso_disc.sso_type, "saml", "oidc")
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Single Sign-On (SSO) is enforced for domain '{email.split('@')[-1]}'. Please log in using enterprise SSO.",
            headers={"X-SSO-Discovery-URL": f"/api/v1/auth/sso/discover?email={email}"},
        )


@app.get("/.well-known/jwks.json", response_model=JWKSResponse)
def jwks_endpoint(response: Response):
    """Step 3 (C-6): Public JWKS endpoint with Cache-Control headers for RSA key rotation."""
    response.headers["Cache-Control"] = "public, max-age=3600"
    return get_jwks()


@app.get("/health/live")
def liveness():
    return {"status": "UP", "service": "auth-service"}


@app.get("/health/ready")
def readiness():
    try:
        jwks = get_jwks()
        if not jwks["keys"]:
            raise RuntimeError("JWKS key store empty.")
        return {"status": "READY", "keys_loaded": len(jwks["keys"])}
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        )


# Step 6 (H-10): Dev Login Hardening & Direct Password Auth
@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def direct_login(req: UserLoginRequest, request: Request):
    if not _settings.auth.enable_dev_login or ENVIRONMENT in ("production", "staging"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Direct password authentication is disabled in non-development profiles. Use Enterprise OIDC SSO.",
        )

    email_clean = str(req.email).lower().strip()
    _check_domain_sso_policy(email_clean, login_method="direct")

    profile = await lifecycle_service.get_or_create_profile(
        email_clean, tenant_id=req.tenant_id, auth_provider="direct"
    )
    assert_login_allowed(profile)

    user_id = profile.user_id
    eff_perms = list(policy_registry.resolve_effective_permissions(profile.roles))
    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "unknown")

    history = await lifecycle_service.get_login_history(user_id)
    suspicious, reason = assess_suspicious_login(
        user_id, ip_addr, user_agent, [h.model_dump() for h in history]
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

    # Step 6 (H-8): Server-side tenant resolution
    resolved_tenant = profile.tenant_id or "default"
    access_token, refresh_token, exp = issue_jwt(
        user_id=user_id,
        email=email_clean,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=resolved_tenant,
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
        tenant_id=resolved_tenant,
        org_id=profile.org_id,
        mfa_verified=not profile.mfa_enabled,
    )


# Multi-Provider OIDC Login Endpoint (Step 7: C-7, H-4)
@app.post("/api/v1/auth/oidc/login", response_model=TokenResponse)
async def multi_provider_login(req: MultiProviderLoginRequest, request: Request):
    try:
        adapter = provider_registry.get_adapter(req.provider)
        result = await adapter.exchange_code(
            req.code, req.redirect_uri, req.code_verifier
        )
    except Exception as exc:
        logger.error(f"OIDC token exchange error ({req.provider}): {exc}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OIDC authentication failed with provider '{req.provider}': {exc}",
        )

    email = result.get("email", "").lower().strip()
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Identity provider '{req.provider}' did not yield a valid email address.",
        )

    # Step 7 (C-7): Reject unverified email for first-time account creation
    email_verified = result.get("email_verified", False)
    _check_domain_sso_policy(email, login_method=req.provider)

    profile = await lifecycle_service.get_profile_by_email(email)
    if not profile:
        if not email_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unverified email address from '{req.provider}'. First-time creation rejected.",
            )
        profile = await lifecycle_service.get_or_create_profile(
            email,
            auth_provider=req.provider,
            display_name=result.get("name"),
            email_verified=True,
        )

    assert_login_allowed(profile)
    await lifecycle_service.link_provider(
        profile.user_id, req.provider, result.get("sub", profile.user_id), email
    )

    eff_perms = list(policy_registry.resolve_effective_permissions(profile.roles))
    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "unknown")
    await lifecycle_service.record_login_attempt(
        profile.user_id, req.provider, ip_addr, user_agent, "success"
    )

    resolved_tenant = profile.tenant_id or "default"
    access_token, refresh_token, exp = issue_jwt(
        user_id=profile.user_id,
        email=email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=resolved_tenant,
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
        tenant_id=resolved_tenant,
        org_id=profile.org_id,
        mfa_verified=True,
    )


# Step 5 (H-1): Token Refresh Endpoint with Rotation & Reuse Detection
@app.post("/api/v1/auth/refresh", response_model=TokenResponse)
async def refresh_tokens(req: TokenRefreshRequest):
    r = await get_redis_client()
    try:
        payload = jwt.decode(
            req.refresh_token,
            options={"verify_signature": False, "verify_exp": True},
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired refresh token: {exc}",
        )

    if payload.get("token_use") != "refresh" and payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Provided token is not a refresh token.",
        )

    jti = payload.get("jti")
    sid = payload.get("sid")
    user_id = payload.get("sub")
    tenant_id = payload.get("tenant_id", "default")

    if r:
        # Step 5: Check if refresh token was already used (reuse detection -> revoke family)
        if jti and await r.get(f"revoked:refresh:{jti}"):
            logger.error(
                f"Refresh token reuse detected for user '{user_id}' (sid: {sid}). Revoking session family."
            )
            if sid:
                await r.setex(f"revoked:sid:{sid}", 86400, "true")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token replay detected. All sessions in this token family have been revoked.",
            )
        if jti:
            await r.setex(f"revoked:refresh:{jti}", 86400, "true")

    profile = await lifecycle_service.get_profile(user_id)
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User profile not found."
        )
    assert_login_allowed(profile)

    eff_perms = list(policy_registry.resolve_effective_permissions(profile.roles))
    access_token, new_refresh_token, exp = issue_jwt(
        user_id=profile.user_id,
        email=profile.email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=tenant_id,
        org_id=profile.org_id,
        email_verified=profile.email_verified,
        mfa_verified=True,
        session_id=sid,
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=exp,
        user_id=profile.user_id,
        email=profile.email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=tenant_id,
        org_id=profile.org_id,
        mfa_verified=True,
    )


# Step 4 (C-3): Secure Single-Use Magic Links
@app.post("/api/v1/auth/magic-link")
async def request_magic_link(req: MagicLinkRequest):
    email_clean = req.email.lower().strip()
    _check_domain_sso_policy(email_clean, login_method="magic_link")

    token = issue_magic_link_token(email_clean)
    r = await get_redis_client()
    if r:
        await r.setex(f"magic_link:{token}", 900, email_clean)

    # Return 200 without exposing token in response body for security
    return {"status": "accepted", "message": "Magic link dispatched if account exists."}


@app.post("/api/v1/auth/magic-link/verify", response_model=TokenResponse)
async def verify_magic_link(req: MagicLinkVerifyRequest, request: Request):
    r = await get_redis_client()
    email = None
    if r:
        email = await r.getdel(f"magic_link:{req.token}")

    if not email:
        email = verify_magic_link_token(req.token)

    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired magic link token.",
        )

    profile = await lifecycle_service.get_or_create_profile(
        email, auth_provider="magic_link", email_verified=True
    )
    assert_login_allowed(profile)

    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "unknown")
    await lifecycle_service.record_login_attempt(
        profile.user_id, "magic_link", ip_addr, user_agent, "success"
    )

    eff_perms = list(policy_registry.resolve_effective_permissions(profile.roles))
    resolved_tenant = profile.tenant_id or "default"
    access_token, refresh_token, exp = issue_jwt(
        user_id=profile.user_id,
        email=email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=resolved_tenant,
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
        tenant_id=resolved_tenant,
        org_id=profile.org_id,
        mfa_verified=True,
    )


# Step 4 (C-1): Authenticated MFA & Reauthentication Routes
@app.post("/api/v1/auth/mfa/setup", response_model=TOTPSetupResponse)
async def setup_mfa(user: CurrentUserDep):
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, user.email)
    backup_codes = [secrets.token_hex(4) for _ in range(8)]
    return TOTPSetupResponse(
        secret=secret, otpauth_url=uri, qr_code_payload=uri, backup_codes=backup_codes
    )


@app.post("/api/v1/auth/mfa/verify")
async def verify_mfa(req: TOTPVerifyRequest, user: CurrentUserDep, secret: str):
    if not verify_totp_code(secret, req.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP verification code.",
        )
    return {"status": "mfa_verified", "user_id": user.user_id}


@app.post("/api/v1/auth/reauthenticate", response_model=ReauthResponse)
async def reauthenticate(req: ReauthRequest, user: CurrentUserDep):
    sudo_token = issue_sudo_token(user.user_id)
    return ReauthResponse(sudo_token=sudo_token, expires_in=900)


# Step 4 (C-1): Authenticated User Account Routes
@app.get("/api/v1/users/me")
async def get_my_profile(user: CurrentUserDep):
    p = await lifecycle_service.get_profile(user.user_id)
    if not p:
        p = await lifecycle_service.get_or_create_profile(
            user.email, tenant_id=user.tenant_id
        )
    return p


@app.put("/api/v1/users/me")
async def update_my_profile(user: CurrentUserDep, req: ProfileUpdateRequest):
    return await lifecycle_service.update_profile(
        user.user_id, **req.model_dump(exclude_unset=True)
    )


@app.get("/api/v1/users/me/sessions")
async def list_my_sessions(user: CurrentUserDep, session_id: str | None = None):
    return await lifecycle_service.list_active_sessions(
        user.user_id, session_id or user.session_id
    )


@app.delete("/api/v1/users/me/sessions/{session_id}")
async def revoke_my_session(user: CurrentUserDep, session_id: str):
    await lifecycle_service.revoke_session(
        user.user_id, session_id, tenant_id=user.tenant_id
    )
    return {"status": "revoked", "session_id": session_id}


@app.post("/api/v1/users/me/logout-all")
async def logout_all_my_devices(user: CurrentUserDep):
    count = await lifecycle_service.logout_all_devices(
        user.user_id, tenant_id=user.tenant_id
    )
    return {"status": "logged_out_all", "revoked_sessions_count": count}


@app.get("/api/v1/users/me/login-history")
async def get_my_login_history(user: CurrentUserDep):
    return await lifecycle_service.get_login_history(user.user_id)


# Step 4 (C-1): Authenticated RBAC Routes
@app.get("/api/v1/rbac/roles")
def list_rbac_roles():
    return list(policy_registry.roles.values())


@app.post("/api/v1/rbac/check-permission")
def check_rbac_permission(req: ResourcePermissionCheckRequest, user: CurrentUserDep):
    allowed = policy_registry.can_access_trip(
        user.user_id, user.roles, trip_owner_id=user.user_id, required_action=req.action
    )
    return {
        "allowed": allowed,
        "resource_id": req.resource_id,
        "action": req.action,
        "roles": user.roles,
    }


# Step 4 (C-2): Domain-verified SSO Discovery
@app.post("/api/v1/auth/sso/discover", response_model=OrgSSODiscoveryResponse)
def discover_sso(req: OrgSSODiscoveryRequest):
    res = enterprise_service.discover_sso_by_domain(req.email)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No enterprise SSO configured or verified for domain.",
        )
    return res


# Step 4 (C-4): SAML 2.0 ACS Assertion Processing
@app.post("/api/v1/auth/saml/acs")
async def saml_acs(req: SAMLACSRequest, request: Request):
    adapter = SAML2Adapter("sp_id", "acs_url")
    res = await adapter.parse_saml_response(req.SAMLResponse)

    email = res["email"].lower().strip()
    _check_domain_sso_policy(email, login_method="saml")

    profile = await lifecycle_service.get_or_create_profile(
        email, auth_provider="saml", email_verified=True
    )
    assert_login_allowed(profile)

    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "unknown")
    await lifecycle_service.record_login_attempt(
        profile.user_id, "saml", ip_addr, user_agent, "success"
    )

    eff_perms = list(policy_registry.resolve_effective_permissions(profile.roles))
    resolved_tenant = profile.tenant_id or "default"
    access_token, refresh_token, exp = issue_jwt(
        user_id=profile.user_id,
        email=email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=resolved_tenant,
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
        tenant_id=resolved_tenant,
        org_id=profile.org_id,
        mfa_verified=True,
    )


# Step 4 (C-2): Protected IdP Configuration Routes
@app.get("/api/v1/orgs/{org_id}/idp-config", response_model=IdPConfigResponse)
def get_idp_configuration(org_id: str, user: CurrentUserDep):
    if user.org_id and user.org_id != org_id and not user.has_role("platform_owner"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized access to organization IdP configuration.",
        )

    cfg = enterprise_service.get_idp_config(org_id)
    if not cfg:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IdP configuration not found for org '{org_id}'.",
        )
    return cfg


@app.post("/api/v1/orgs/{org_id}/idp-config", response_model=IdPConfigResponse)
def update_idp_configuration(org_id: str, req: IdPConfigRequest, user: CurrentUserDep):
    if user.org_id and user.org_id != org_id and not user.has_role("platform_owner"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized write to organization IdP configuration.",
        )

    if (
        not user.has_permission("sso:manage")
        and not user.has_role("platform_owner")
        and not user.has_role("organization_owner")
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission 'sso:manage' required.",
        )

    req.org_id = org_id
    return enterprise_service.set_idp_config(req)


# Step 4 (C-2): Token-Protected SCIM 2.0 Provisioning Endpoints
@app.get("/scim/v2/Users", response_model=SCIMListResponse)
async def scim_list_users(
    filter: str | None = None,
    startIndex: int = 1,
    count: int = 100,
    auth: str = Depends(verify_scim_token),
):
    return await scim_service.list_users(filter, startIndex, count)


@app.post("/scim/v2/Users", response_model=SCIMUserSchema, status_code=201)
async def scim_create_user(
    user: SCIMUserSchema, auth: str = Depends(verify_scim_token)
):
    return await scim_service.create_user(user)


@app.get("/scim/v2/Users/{user_id}", response_model=SCIMUserSchema)
async def scim_get_user(user_id: str, auth: str = Depends(verify_scim_token)):
    u = await scim_service.get_user(user_id)
    if not u:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="SCIM User not found."
        )
    return u


@app.put("/scim/v2/Users/{user_id}", response_model=SCIMUserSchema)
async def scim_update_user(
    user_id: str, user: SCIMUserSchema, auth: str = Depends(verify_scim_token)
):
    return await scim_service.update_user(user_id, user)


@app.delete("/scim/v2/Users/{user_id}", status_code=204)
async def scim_delete_user(user_id: str, auth: str = Depends(verify_scim_token)):
    await scim_service.delete_user(user_id)
    return Response(status_code=204)


@app.get("/scim/v2/Groups", response_model=SCIMListResponse)
async def scim_list_groups(auth: str = Depends(verify_scim_token)):
    return await scim_service.list_groups()


@app.post("/scim/v2/Groups", response_model=SCIMGroupSchema, status_code=201)
async def scim_create_group(
    group: SCIMGroupSchema, auth: str = Depends(verify_scim_token)
):
    return await scim_service.create_group(group)


# Step 5 (C-5): Token & Session Revocation Endpoint
@app.post("/api/v1/auth/revoke")
async def revoke_token(req: TokenRevokeRequest, user: CurrentUserDep):
    r = await get_redis_client()
    if r and req.token:
        try:
            unverified_claims = jwt.decode(
                req.token, options={"verify_signature": False}
            )
            jti = unverified_claims.get("jti")
            sid = unverified_claims.get("sid")
            if jti:
                await r.setex(f"revoked:{jti}", 86400, "true")
            if sid:
                await r.setex(f"revoked:sid:{sid}", 86400, "true")
        except Exception as exc:
            logger.debug(f"Error parsing token for revocation: {exc}")

    return {"status": "revoked"}
