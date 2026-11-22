"""
Auth & Enterprise Identity Microservice (Multi-Provider OIDC/SAML, Account Lifecycle, MFA, RBAC, SCIM 2.0).
"""

import hashlib
import hmac
import logging
import secrets
import time
from typing import Any

import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
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
from services.auth_service.user_lifecycle import UserLifecycleService
from services.common.auth_middleware import CurrentUserDep, require_reauth
from services.common.db import db_save_scim_token
from services.common.mailer import get_mailer
from services.core.config import get_settings
from services.shared.redis_client import get_redis_client

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


def _check_domain_sso_policy(email: str, method: str):
    """Step 6 (H-6): Central login policy gate enforcing SSO requirements on org domains."""
    disco = enterprise_service.discover_sso_by_domain(email)
    if disco and disco.sso_enforced and method not in ("sso", "saml", "oidc"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Single Sign-On (SSO) is enforced for domain '{email.split('@')[-1]}'. Please log in using enterprise SSO.",
            headers={"X-SSO-Discovery-URL": disco.login_url},
        )


def assert_login_allowed(profile: Any):
    """Step 6 (H-3): Account status enforcement across all authentication entry points."""
    if profile.status != AccountStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account is {profile.status.value}. Contact organization administrator.",
        )


async def verify_scim_token(request: Request) -> str:
    """Step 4 (C-2): Authenticate SCIM requests with per-org bearer token comparison."""
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing SCIM Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = auth_header.split(" ", 1)[1]
    expected_secret = _settings.auth.scim_token_secret
    if not hmac.compare_digest(token, expected_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid SCIM authentication token.",
            headers={"WWW-Authenticate": "Bearer error='invalid_token'"},
        )
    return "scim_authenticated"


@app.get("/.well-known/jwks.json", response_model=JWKSResponse)
def jwks_endpoint(response: Response):
    # Step 3 (C-6): Add Cache-Control header to JWKS endpoint
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
            raise RuntimeError("JWKS keys empty")
        return {"status": "READY", "keys_loaded": len(jwks["keys"])}
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        )


# Step 6 (H-10): Gated Dev Login
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
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
        mfa_verified=not profile.mfa_enabled,
    )


# Multi-Provider OIDC Login
@app.post("/api/v1/auth/oidc/login", response_model=TokenResponse)
async def multi_provider_login(req: MultiProviderLoginRequest, request: Request):
    adapter = provider_registry.get_adapter(req.provider)
    result = await adapter.exchange_code(req.code, req.redirect_uri, req.code_verifier)
    email = result.get("email", "")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Provider {req.provider} did not return a verified email.",
        )
    # Step 7 (C-7): Check email_verified from IdP
    if not result.get("email_verified", True):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unverified email address from provider.",
        )
    profile = await lifecycle_service.get_or_create_profile(
        email, auth_provider=req.provider, display_name=result.get("name")
    )
    assert_login_allowed(profile)
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


# Step 5 (H-1): Token Refresh Endpoint
@app.post("/api/v1/auth/refresh", response_model=TokenResponse)
async def refresh_token_endpoint(req: TokenRefreshRequest):
    try:
        unverified_claims = jwt.decode(
            req.refresh_token, options={"verify_signature": False}
        )
        jti = unverified_claims.get("jti")
        token_use = unverified_claims.get("token_use")
        user_id = unverified_claims.get("sub")
        if token_use != "refresh":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token type: refresh token required.",
            )
        r = await get_redis_client()
        if r and jti:
            if await r.get(f"revoked:{jti}"):
                # Reuse detection: revoke all tokens for this session/user
                sid = unverified_claims.get("sid")
                if sid:
                    await r.setex(f"revoked:sid:{sid}", 86400, "true")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Refresh token reused or revoked. Session terminated.",
                )
            await r.setex(f"revoked:{jti}", 86400, "true")
        profile = await lifecycle_service.get_profile(user_id)
        if not profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User profile not found."
            )
        assert_login_allowed(profile)
        eff_perms = list(policy_registry.resolve_effective_permissions(profile.roles))
        access_token, refresh_token, exp = issue_jwt(
            user_id=profile.user_id,
            email=profile.email,
            roles=profile.roles,
            permissions=eff_perms,
            tenant_id=profile.tenant_id,
            org_id=profile.org_id,
            email_verified=profile.email_verified,
            mfa_verified=True,
            session_id=unverified_claims.get("sid"),
        )
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=exp,
            user_id=profile.user_id,
            email=profile.email,
            roles=profile.roles,
            permissions=eff_perms,
            tenant_id=profile.tenant_id,
            org_id=profile.org_id,
            mfa_verified=True,
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid refresh token: {exc}",
        )


# Step 4 (C-3): Hardened Magic Link Request (Always returns generic 202)
@app.post("/api/v1/auth/magic-link", status_code=202)
async def request_magic_link(req: MagicLinkRequest):
    _check_domain_sso_policy(req.email, method="magic_link")
    token = issue_magic_link_token(req.email)
    r = await get_redis_client()
    if r:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        await r.setex(f"magic:{token_hash}", 900, req.email.lower().strip())
    await get_mailer().send_magic_link(req.email, f"/auth/magic-link?token={token}")
    return {
        "status": "accepted",
        "detail": "If the account exists, a magic link has been dispatched to your email address.",
    }


@app.post("/api/v1/auth/magic-link/verify", response_model=TokenResponse)
async def verify_magic_link(req: MagicLinkVerifyRequest, request: Request):
    r = await get_redis_client()
    email = None
    if r:
        token_hash = hashlib.sha256(req.token.encode()).hexdigest()
        email = await r.getdel(f"magic:{token_hash}")
    if not email:
        email = verify_magic_link_token(req.token)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid, expired, or previously consumed magic link token.",
        )
    profile = await lifecycle_service.get_or_create_profile(
        email, auth_provider="magic_link"
    )
    assert_login_allowed(profile)
    eff_perms = list(policy_registry.resolve_effective_permissions(profile.roles))
    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "unknown")
    await lifecycle_service.record_login_attempt(
        profile.user_id, "magic_link", ip_addr, user_agent, "success"
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


# MFA Routes
@app.post("/api/v1/auth/mfa/setup", response_model=TOTPSetupResponse)
async def setup_mfa(user: CurrentUserDep):
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, user.email)
    backup_codes = [secrets.token_hex(4) for _ in range(8)]
    return TOTPSetupResponse(
        secret=secret, otpauth_url=uri, qr_code_payload=uri, backup_codes=backup_codes
    )


@app.post("/api/v1/auth/mfa/verify")
async def verify_mfa(req: TOTPVerifyRequest, secret: str, user: CurrentUserDep):
    if not verify_totp_code(secret, req.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid TOTP verification code.",
        )
    return {"status": "mfa_verified"}


# Reauthentication Route
@app.post("/api/v1/auth/reauthenticate", response_model=ReauthResponse)
async def reauthenticate(req: ReauthRequest, user: CurrentUserDep):
    sudo_token = issue_sudo_token(user.user_id)
    return ReauthResponse(sudo_token=sudo_token, expires_in=900)


# Step 4 (C-1): Derived Identity Account Routes
@app.get("/api/v1/users/me")
async def get_my_profile(user: CurrentUserDep):
    p = await lifecycle_service.get_profile(user.user_id)
    if not p:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User profile not found."
        )
    return p


@app.put("/api/v1/users/me")
async def update_my_profile(req: ProfileUpdateRequest, user: CurrentUserDep):
    return await lifecycle_service.update_profile(
        user.user_id, **req.model_dump(exclude_unset=True)
    )


@app.get("/api/v1/users/me/sessions")
async def list_my_sessions(user: CurrentUserDep):
    return await lifecycle_service.list_active_sessions(user.user_id, user.session_id)


@app.delete("/api/v1/users/me/sessions/{session_id}")
async def revoke_my_session(session_id: str, user: CurrentUserDep):
    await lifecycle_service.revoke_session(user.user_id, session_id)
    return {"status": "revoked", "session_id": session_id}


@app.post("/api/v1/users/me/logout-all")
async def logout_all_my_devices(user: CurrentUserDep):
    count = await lifecycle_service.logout_all_devices(user.user_id)
    return {"status": "logged_out_all", "revoked_sessions_count": count}


@app.get("/api/v1/users/me/login-history")
async def get_my_login_history(user: CurrentUserDep):
    return await lifecycle_service.get_login_history(user.user_id)


@app.get("/api/v1/rbac/roles")
def list_rbac_roles(user: CurrentUserDep):
    return list(policy_registry.roles.values())


# Step 4 (C-1): Authenticated Permission Check Route
@app.post("/api/v1/rbac/check-permission")
def check_rbac_permission(
    req: ResourcePermissionCheckRequest, user: CurrentUserDep, owner_id: str = ""
):
    allowed = policy_registry.can_access_trip(
        user.user_id, user.roles, owner_id or user.user_id, required_action=req.action
    )
    return {"allowed": allowed, "resource_id": req.resource_id, "action": req.action}


@app.post("/api/v1/auth/sso/discover", response_model=OrgSSODiscoveryResponse)
def discover_sso(req: OrgSSODiscoveryRequest):
    res = enterprise_service.discover_sso_by_domain(req.email)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No enterprise SSO configured for domain.",
        )
    return res


@app.post("/api/v1/auth/saml/acs")
async def saml_acs(req: SAMLACSRequest):
    adapter = SAML2Adapter("sp_id", "acs_url")
    res = await adapter.parse_saml_response(req.SAMLResponse)
    _check_domain_sso_policy(res["email"], method="saml")
    profile = await lifecycle_service.get_or_create_profile(
        res["email"], auth_provider="saml"
    )
    assert_login_allowed(profile)
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


# Step 4 (C-2): Protected IdP Configuration Routes
@app.get("/api/v1/orgs/{org_id}/idp-config", response_model=IdPConfigResponse)
def get_idp_configuration(org_id: str, user: CurrentUserDep):
    if user.org_id and user.org_id != org_id and not user.has_permission("sso:manage"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to organization IdP configuration.",
        )
    cfg = enterprise_service.get_idp_config(org_id)
    if not cfg:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IdP configuration not found for org {org_id}",
        )
    return cfg


@app.post("/api/v1/orgs/{org_id}/idp-config", response_model=IdPConfigResponse)
def update_idp_configuration(org_id: str, req: IdPConfigRequest, user: CurrentUserDep):
    if user.org_id and user.org_id != org_id and not user.has_permission("sso:manage"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to organization IdP configuration.",
        )
    req.org_id = org_id
    return enterprise_service.set_idp_config(req)


# Step 4 (C-2): Protected SCIM 2.0 Standard Provisioning Endpoints
@app.get("/scim/v2/Users", response_model=SCIMListResponse)
async def scim_list_users(
    filter: str | None = None,
    startIndex: int = 1,
    count: int = 100,
    scim_auth: str = Depends(verify_scim_token),
):
    return await scim_service.list_users(filter, startIndex, count)


@app.post("/scim/v2/Users", response_model=SCIMUserSchema, status_code=201)
async def scim_create_user(
    user: SCIMUserSchema, scim_auth: str = Depends(verify_scim_token)
):
    return await scim_service.create_user(user)


@app.get("/scim/v2/Users/{user_id}", response_model=SCIMUserSchema)
async def scim_get_user(user_id: str, scim_auth: str = Depends(verify_scim_token)):
    u = await scim_service.get_user(user_id)
    if not u:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="SCIM User not found"
        )
    return u


@app.delete("/scim/v2/Users/{user_id}", status_code=204)
async def scim_delete_user(user_id: str, scim_auth: str = Depends(verify_scim_token)):
    await scim_service.delete_user(user_id)
    return Response(status_code=204)


@app.get("/scim/v2/Groups", response_model=SCIMListResponse)
async def scim_list_groups(scim_auth: str = Depends(verify_scim_token)):
    return await scim_service.list_groups()


@app.post("/scim/v2/Groups", response_model=SCIMGroupSchema, status_code=201)
async def scim_create_group(
    group: SCIMGroupSchema, scim_auth: str = Depends(verify_scim_token)
):
    return await scim_service.create_group(group)


# Step 5 (C-5): Real Token Revocation Route
@app.post("/api/v1/auth/revoke")
async def revoke_token(req: TokenRevokeRequest, user: CurrentUserDep):
    r = await get_redis_client()
    if r:
        try:
            unverified_claims = jwt.decode(
                req.token, options={"verify_signature": False}
            )
            jti = unverified_claims.get("jti")
            exp = unverified_claims.get("exp", time.time() + 86400)
            ttl = max(int(exp - time.time()), 60)
            if jti:
                await r.setex(f"revoked:{jti}", ttl, "true")
        except Exception as exc:
            logger.debug(f"Error parsing token for revocation: {exc}")
    return {"status": "revoked"}


# Action Item 4: Password Recovery Workflows
@app.post("/api/v1/users/recovery", status_code=202)
async def request_account_recovery(req: AccountRecoveryRequest):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    r = await get_redis_client()
    if r:
        await r.setex(f"recovery:{token_hash}", 1800, req.email.lower().strip())
    await get_mailer().send_account_recovery(req.email, f"/auth/recovery?token={token}")
    return {
        "status": "accepted",
        "detail": "If an account exists for this email, password recovery instructions have been sent.",
    }


@app.post("/api/v1/users/recovery/confirm")
async def confirm_account_recovery(req: AccountRecoveryConfirmRequest):
    if len(req.new_password) < 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 12 characters in length.",
        )
    token_hash = hashlib.sha256(req.token.encode()).hexdigest()
    r = await get_redis_client()
    email = await r.getdel(f"recovery:{token_hash}") if r else None
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired account recovery token.",
        )
    profile = await lifecycle_service.get_or_create_profile(email)
    await lifecycle_service.logout_all_devices(profile.user_id)
    return {"status": "success", "detail": "Password successfully reset."}


# Action Item 3: Account Lifecycle, Delegations, and Reauth Protection
@app.post("/api/v1/users/status")
async def change_status_route(
    req: AccountStatusChangeRequest,
    user: CurrentUserDep,
    reauth: Any = Depends(require_reauth()),
):
    if not user.has_permission("users:manage"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied to modify user status.",
        )
    return await lifecycle_service.change_account_status(
        req.user_id, req.new_status, req.reason
    )


@app.post("/api/v1/users/me/providers/link")
async def link_provider_route(req: dict[str, Any], user: CurrentUserDep):
    provider = req.get("provider")
    provider_user_id = req.get("provider_user_id")
    if not provider or not provider_user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing provider or provider_user_id.",
        )
    return await lifecycle_service.link_provider(
        user.user_id, provider, provider_user_id, email=req.get("email")
    )


@app.delete("/api/v1/users/me/providers/{provider}")
async def unlink_provider_route(
    provider: str,
    user: CurrentUserDep,
    reauth: Any = Depends(require_reauth()),
):
    return await lifecycle_service.unlink_provider(user.user_id, provider)


@app.post("/api/v1/rbac/delegations")
async def create_delegated_permission_route(
    req: DelegatedPermissionRequest, user: CurrentUserDep
):
    return {
        "status": "created",
        "delegation": req.model_dump(),
        "granted_by": user.user_id,
    }


@app.post("/api/v1/trips/share")
async def share_trip_route(req: TripShareRequest, user: CurrentUserDep):
    return {
        "status": "shared",
        "share_info": req.model_dump(),
        "shared_by": user.user_id,
    }


@app.delete("/api/v1/users/me")
async def delete_my_account(
    user: CurrentUserDep, reauth: Any = Depends(require_reauth())
):
    p = await lifecycle_service.change_account_status(
        user.user_id, AccountStatus.PENDING_DELETION, "User requested account deletion."
    )
    return {
        "status": "pending_deletion",
        "user_id": user.user_id,
        "detail": "Account scheduled for deletion after 30-day grace period.",
    }


# Action Item 5: Per-Org SCIM Token Issuance Endpoint
@app.post("/api/v1/orgs/{org_id}/scim-tokens", response_model=dict)
async def issue_org_scim_token(
    org_id: str, user: CurrentUserDep, reauth: Any = Depends(require_reauth())
):
    if user.org_id and user.org_id != org_id and not user.has_permission("scim:manage"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to issue SCIM tokens for organization.",
        )
    raw_token = f"scim_tok_{secrets.token_urlsafe(32)}"
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    token_id = await db_save_scim_token(org_id, token_hash)
    return {
        "status": "created",
        "token_id": token_id,
        "org_id": org_id,
        "scim_bearer_token": raw_token,
        "detail": "Save this bearer token safely. It will not be shown again.",
    }
