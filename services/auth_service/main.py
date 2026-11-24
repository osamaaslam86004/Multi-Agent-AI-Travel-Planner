"""
Auth & Identity Microservice REST API.
Handles direct login, multi-provider OIDC/SAML 2.0 authentication, MFA challenges,
user account lifecycle, invitations, grace period soft-deletion, provider linking,
step-up reauthentication, SCIM 2.0 with filtering/PATCH/ETags, and RBAC.
"""
import hashlib
import json
import logging
import secrets
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

from services.auth_service.adapters import (
    GenericOIDCAdapter,
    MicrosoftEntraAdapter,
    SAML2Adapter,
    provider_registry,
)
from services.auth_service.enterprise import enterprise_service, scim_service
from services.auth_service.models import (
    AccountRecoveryConfirmRequest,
    AccountRecoveryRequest,
    AccountStatus,
    AccountStatusChangeRequest,
    DelegatedPermissionRequest,
    DeviceTrustRequest,
    EmailVerifyRequest,
    IdPConfigRequest,
    IdPConfigResponse,
    InvitationAcceptRequest,
    InvitationCreateRequest,
    InvitationResponse,
    JWKSResponse,
    LinkProviderRequest,
    MagicLinkRequest,
    MagicLinkVerifyRequest,
    MFAVerifyLoginRequest,
    MultiProviderLoginRequest,
    OrgSSODiscoveryRequest,
    OrgSSODiscoveryResponse,
    ProfileUpdateRequest,
    ReauthRequest,
    ReauthResponse,
    RoleAssignmentRequest,
    RoleRevocationRequest,
    SAMLACSRequest,
    SCIMGroupSchema,
    SCIMListResponse,
    SCIMPatchRequest,
    SCIMUserSchema,
    SecurityEventResponse,
    SessionRevokeRequest,
    SwitchOrgRequest,
    TokenRefreshRequest,
    TokenResponse,
    TokenRevokeRequest,
    TOTPSetupResponse,
    TOTPVerifyRequest,
    TripShareRequest,
    UserLoginRequest,
    UserProfile,
)
from services.auth_service.rbac import ROLES_CATALOG, policy_registry
from services.auth_service.security import (
    assess_suspicious_login,
    async_hash_password,
    compute_device_fingerprint,
    decode_refresh_token,
    decode_signed_token,
    decode_signed_token_allow_expired,
    generate_totp_secret,
    get_jwks,
    get_totp_uri,
    hash_password,
    issue_jwt,
    issue_sudo_token,
    verify_password,
    verify_totp_code,
)
from services.auth_service.security_state import (
    consume_backup_code,
    consume_mfa_enrollment,
    consume_mfa_login_challenge,
    delete_mfa_secret,
    digest,
    get_mfa_secret,
    oauth_begin,
    oauth_consume,
    put_once,
    refresh_consume,
    refresh_register,
    save_backup_codes,
    save_mfa_secret,
    store_mfa_login_challenge,
    store_mfa_secret,
)
from services.auth_service.user_lifecycle import lifecycle_service
from services.common.auth_middleware import (
    AuthenticatedUser,
    get_current_user,
    require_reauth,
)
from services.common.db import (
    close_db_pool,
    db_assign_role,
    db_delete_scim_token,
    db_get_federated_identity,
    db_get_scim_token_by_hash,
    db_get_user_by_email,
    db_get_user_org_memberships,
    db_get_user_password,
    db_list_scim_tokens,
    db_revoke_role,
    db_save_delegated_permission,
    db_save_scim_token,
    db_save_trip_share,
    db_save_user_password,
    db_upsert_user_profile,
    get_trip_by_id,
    init_db_pool,
    init_identity_schema,
)
from services.common.mailer import get_mailer
from services.core.config import get_settings
from services.shared.redis_client import get_redis_client

logger = logging.getLogger("travelbrain.auth_service")
_settings = get_settings()
ENVIRONMENT = _settings.app.environment.lower()
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Auth & Identity Service dependencies...")
    try:
        from services.common.telemetry import (
            configure_structured_logging,
            setup_telemetry,
        )
        configure_structured_logging()
        setup_telemetry(service_name="auth-service")
    except Exception as exc:
        logger.warning(f"Telemetry initialization warning: {exc}")
    try:
        pool = await init_db_pool()
        if pool is not None:
            async with pool.connection() as conn:
                init_identity_schema(conn)
    except Exception as exc:
        logger.warning(f"Database initialization warning: {exc}")
    try:
        r = await get_redis_client()
        if r is not None:
            await r.ping()
    except Exception as exc:
        logger.warning(f"Redis initialization warning: {exc}")
    yield
    logger.info("Shutting down Auth & Identity Service dependencies...")
    await close_db_pool()
app = FastAPI(
    title="TravelBrain Enterprise Auth & Identity Service",
    version="2.0.0",
    docs_url="/docs" if ENVIRONMENT == "development" else None,
    lifespan=lifespan,
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
    if ENVIRONMENT in ("production", "staging") and r is None:
        raise HTTPException(
            status_code=503, detail="Redis is required for auth readiness"
        )
    from services.common.db import init_db_pool
    pool = await init_db_pool()
    if ENVIRONMENT in ("production", "staging") and pool is None:
        raise HTTPException(
            status_code=503, detail="PostgreSQL is required for auth readiness"
        )
    return {
        "status": "READY",
        "redis": "connected" if r else "disconnected",
        "postgres": "connected" if pool else "development-memory",
    }
@app.get("/.well-known/jwks.json", response_model=JWKSResponse)
def jwks_endpoint():
    return get_jwks()
# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def assert_admin_mfa_enrolled(profile: UserProfile):
    admin_roles = {
        "platform_owner",
        "platform_administrator",
        "admin",
        "organization_owner",
        "organization_administrator",
    }
    if (
        _settings.auth.require_mfa_for_admins
        and any(role in admin_roles for role in profile.roles)
        and not profile.mfa_enabled
    ):
        raise HTTPException(
            status_code=403,
            detail="Administrator MFA enrollment is required before login.",
        )
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
async def _check_domain_sso_policy(email: str, method: str = "direct"):
    if "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email address required.")
    domain = email.rsplit("@", 1)[-1].lower().strip()
    configs = await enterprise_service.list_idp_configs()
    for config in configs:
        allowed = {d.lower().strip().lstrip("@") for d in config.allowed_domains}
        if config.enforce_sso and domain in allowed:
            expected = config.idp_name.lower().strip()
            permitted = {expected}
            if config.sso_type == "oidc":
                permitted.update({"generic_oidc", "entra", "google", "github"})
            elif config.sso_type == "saml":
                permitted.add("saml")
            if method.lower().strip() not in permitted:
                raise HTTPException(
                    status_code=403,
                    detail="This email domain requires its configured enterprise identity provider.",
                )
async def _register_refresh_token(token: str):
    claims = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
    await refresh_register(
        claims["jti"], claims["sub"], claims["sid"], int(claims["exp"])
    )
def _require_org_scope(user: AuthenticatedUser, org_id: str, permission: str):
    if not user.has_permission(permission):
        raise HTTPException(
            status_code=403, detail="Required organization permission denied."
        )
    if user.org_id != org_id and not user.has_permission("platform:admin"):
        raise HTTPException(status_code=403, detail="Organization scope mismatch.")
async def _check_device_trust(user_id: str, request: Request):
    if not _settings.auth.enforce_device_trust:
        return
    r = await get_redis_client()
    if r is None:
        raise HTTPException(
            status_code=503, detail="Device trust validation unavailable"
        )
    client_ip = request.headers.get("X-Forwarded-For") or request.headers.get("X-Client-IP") or (request.client.host if request.client else "127.0.0.1")
    user_agent = request.headers.get("X-Client-User-Agent") or request.headers.get("User-Agent", "unknown")
    fingerprint = compute_device_fingerprint(user_agent, client_ip)
    keys = await r.keys(f"trusted_device:{user_id}:*")
    if not keys:
        await r.set(f"trusted_device:{user_id}:{fingerprint}", "1", ex=86400*90)
        return
    if not await r.get(f"trusted_device:{user_id}:{fingerprint}"):
        raise HTTPException(
            status_code=403,
            detail="Untrusted device. Device trust registration required.",
        )
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
    await _check_domain_sso_policy(email_clean, method="direct")
    redis_state = await get_redis_client()
    lock_key = f"login_lockout:{digest(email_clean)}"
    failure_key = f"login_failures:{digest(email_clean)}"
    if redis_state and await redis_state.get(lock_key):
        raise HTTPException(
            status_code=429,
            detail="Account temporarily locked after failed login attempts.",
        )
    profile = await lifecycle_service.get_or_create_profile(
        email_clean, tenant_id=req.tenant_id, auth_provider="direct"
    )
    assert_login_allowed(profile)
    assert_admin_mfa_enrolled(profile)
    user_id = profile.user_id
    stored_hash = await db_get_user_password(user_id)
    if stored_hash:
        if not verify_password(req.password, stored_hash):
            if redis_state:
                failures = await redis_state.incr(failure_key)
                if failures == 1:
                    await redis_state.expire(
                        failure_key, _settings.auth.lockout_duration_seconds
                    )
                if failures >= _settings.auth.max_failed_login_attempts:
                    await redis_state.set(
                        lock_key, "1", ex=_settings.auth.lockout_duration_seconds
                    )
            await lifecycle_service.record_login_attempt(
                user_id,
                "direct",
                request.client.host if request.client else "0.0.0.0",
                request.headers.get("User-Agent", "unknown"),
                "failure",
            )
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        if redis_state:
            await redis_state.delete(failure_key, lock_key)
    else:
        if len(req.password) < _settings.auth.min_password_length:
            raise HTTPException(
                status_code=400,
                detail=f"Password must be at least {_settings.auth.min_password_length} characters.",
            )
        await db_save_user_password(user_id, hash_password(req.password))
    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "unknown")
    suspicious, reason = assess_suspicious_login(
        user_id,
        ip_addr,
        user_agent,
        [h.model_dump() for h in await lifecycle_service.get_login_history(user_id)],
    )
    if suspicious and _settings.auth.enable_suspicious_login_detection:
        await lifecycle_service.record_login_attempt(
            user_id,
            "direct",
            ip_addr,
            user_agent,
            "failure",
            suspicious=True,
            details=reason,
        )
        raise HTTPException(
            status_code=403,
            detail="Suspicious login blocked. Verify account security before retrying.",
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
    if profile.mfa_enabled or suspicious:
        challenge_token = await store_mfa_login_challenge(
            user_id=user_id,
            email=email_clean,
            tenant_id=profile.tenant_id,
            org_id=profile.org_id,
            roles=profile.roles,
            ttl=300,
        )
        return TokenResponse(
            access_token="",
            refresh_token="",
            expires_in=300,
            user_id=user_id,
            email=email_clean,
            roles=profile.roles,
            permissions=[],
            tenant_id=profile.tenant_id,
            org_id=profile.org_id,
            mfa_verified=False,
            mfa_required=True,
            mfa_challenge_token=challenge_token,
            mfa_methods=["totp", "backup_code"],
        )
    await _check_device_trust(user_id, request)
    eff_perms = list(policy_registry.resolve_effective_permissions(profile.roles))
    access_token, refresh_token, exp = issue_jwt(
        user_id=user_id,
        email=email_clean,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
    )
    await _register_refresh_token(refresh_token)
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
        mfa_verified=True,
    )
@app.post("/api/v1/auth/mfa/verify-login", response_model=TokenResponse)
async def mfa_verify_login(req: MFAVerifyLoginRequest, request: Request):
    challenge = await consume_mfa_login_challenge(req.mfa_challenge_token)
    if not challenge:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA challenge token.",
        )
    user_id = challenge["user_id"]
    totp_valid = False
    if req.totp_code:
        secret = await get_mfa_secret(user_id)
        if secret and verify_totp_code(secret, req.totp_code):
            totp_valid = True
    elif req.backup_code and await consume_backup_code(user_id, req.backup_code):
        totp_valid = True
    if not totp_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA verification code or backup code.",
        )
    profile = await lifecycle_service.get_profile(user_id)
    if not profile:
        raise HTTPException(status_code=401, detail="User account not found.")
    eff_perms = list(policy_registry.resolve_effective_permissions(challenge["roles"]))
    access_token, refresh_token, exp = issue_jwt(
        user_id=user_id,
        email=challenge["email"],
        roles=challenge["roles"],
        permissions=eff_perms,
        tenant_id=challenge["tenant_id"],
        org_id=challenge["org_id"],
    )
    await _register_refresh_token(refresh_token)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=exp,
        user_id=user_id,
        email=challenge["email"],
        roles=challenge["roles"],
        permissions=eff_perms,
        tenant_id=challenge["tenant_id"],
        org_id=challenge["org_id"],
        mfa_verified=True,
    )
@app.get("/api/v1/auth/oidc/authorize-url")
async def oidc_authorize_url(
    provider: str,
    redirect_uri: str,
    tenant_id: str = "default",
    org_id: str | None = None,
):
    if not redirect_uri.startswith("https://") and ENVIRONMENT in (
        "production",
        "staging",
    ):
        raise HTTPException(status_code=400, detail="HTTPS redirect URI required")
    if provider in ("generic_oidc", "entra") and org_id:
        cfg = await enterprise_service.get_idp_config_raw(org_id)
        if not cfg or cfg.get("sso_type") != "oidc" or not cfg.get("client_secret"):
            raise HTTPException(
                status_code=400, detail="Organization OIDC configuration unavailable"
            )
        if provider == "entra":
            issuer_url = cfg.get("issuer_url", "")
            tenant_id = (
                issuer_url.rstrip("/").split("/")[-2]
                if issuer_url.rstrip("/").endswith("/v2.0")
                else issuer_url.rstrip("/").split("/")[-1]
            )
            adapter = MicrosoftEntraAdapter(
                cfg["client_id"], cfg["client_secret"], tenant_id=tenant_id
            )
        else:
            adapter = GenericOIDCAdapter(
                cfg["issuer_url"], cfg["client_id"], cfg["client_secret"]
            )
    elif provider == "generic_oidc":
        if not org_id:
            raise HTTPException(
                status_code=400, detail="Organization is required for Generic OIDC"
            )
        cfg = await enterprise_service.get_idp_config(org_id)
        if (
            not cfg
            or cfg.sso_type != "oidc"
            or not cfg.issuer_url
            or not cfg.client_secret
        ):
            raise HTTPException(
                status_code=400, detail="Generic OIDC is not configured"
            )
        adapter = GenericOIDCAdapter(cfg.issuer_url, cfg.client_id, cfg.client_secret)
    else:
        try:
            adapter = provider_registry.get_adapter(provider)
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail="Unsupported identity provider"
            ) from exc
    transaction = await oauth_begin(provider, redirect_uri, tenant_id, org_id)
    auth_url = await adapter.get_auth_url(
        transaction["state"],
        redirect_uri,
        transaction["challenge"],
        transaction["nonce"],
    )
    return {"authorization_url": auth_url, "state": transaction["state"]}
@app.post("/api/v1/auth/oidc/login", response_model=TokenResponse)
async def multi_provider_login(req: MultiProviderLoginRequest, request: Request):
    tx = await oauth_consume(req.state, req.provider)
    if tx.get("purpose", "login") != "login":
        raise HTTPException(
            status_code=401, detail="OAuth transaction purpose mismatch"
        )
    if req.redirect_uri != tx.get("redirect_uri"):
        raise HTTPException(
            status_code=401, detail="OAuth redirect URI binding mismatch"
        )
    verifier = tx.get("verifier")
    if req.code_verifier and not secrets.compare_digest(
        req.code_verifier, verifier or ""
    ):
        raise HTTPException(status_code=401, detail="OAuth PKCE verifier mismatch")
    if req.provider in ("generic_oidc", "entra") and tx.get("org_id"):
        cfg = await enterprise_service.get_idp_config_raw(tx["org_id"])
        if not cfg or not cfg.get("client_secret"):
            raise HTTPException(
                status_code=400, detail="Organization OIDC configuration unavailable"
            )
        if req.provider == "entra":
            issuer_url = cfg.get("issuer_url", "")
            tenant_id = (
                issuer_url.rstrip("/").split("/")[-2]
                if issuer_url.rstrip("/").endswith("/v2.0")
                else issuer_url.rstrip("/").split("/")[-1]
            )
            adapter = MicrosoftEntraAdapter(
                cfg["client_id"], cfg["client_secret"], tenant_id=tenant_id
            )
        else:
            adapter = GenericOIDCAdapter(
                cfg["issuer_url"], cfg["client_id"], cfg["client_secret"]
            )
    else:
        adapter = provider_registry.get_adapter(req.provider)
    tokens = await adapter.exchange_code(
        req.code, req.redirect_uri, verifier, tx.get("nonce")
    )
    if req.provider != "github" and tokens.get("raw_claims", {}).get("nonce") != tx.get(
        "nonce"
    ):
        raise HTTPException(status_code=401, detail="OIDC nonce validation failed")
    email = tokens.get("email")
    if not email or not tokens.get("email_verified"):
        raise HTTPException(
            status_code=400, detail="Provider must return a verified email address."
        )
    await _check_domain_sso_policy(email, method=req.provider)
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
    assert_admin_mfa_enrolled(profile)
    if tx.get("org_id"):
        if profile.org_id and profile.org_id != tx["org_id"]:
            raise HTTPException(
                status_code=403, detail="User organization scope mismatch"
            )
        profile.org_id = tx["org_id"]
        mapped_roles = await enterprise_service.map_idp_groups_to_roles(
            tx["org_id"], tokens.get("groups", [])
        )
        token_roles = sorted(set(profile.roles + mapped_roles))
    else:
        token_roles = profile.roles
    user_id = profile.user_id
    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "unknown")
    suspicious, reason = assess_suspicious_login(
        user_id,
        ip_addr,
        user_agent,
        [h.model_dump() for h in await lifecycle_service.get_login_history(user_id)],
    )
    if profile.mfa_enabled or suspicious:
        challenge_token = await store_mfa_login_challenge(
            user_id=user_id,
            email=profile.email,
            tenant_id=profile.tenant_id,
            org_id=profile.org_id,
            roles=token_roles,
            ttl=300,
        )
        return TokenResponse(
            access_token="",
            refresh_token="",
            expires_in=300,
            user_id=user_id,
            email=profile.email,
            roles=token_roles,
            permissions=[],
            tenant_id=profile.tenant_id,
            org_id=profile.org_id,
            mfa_verified=False,
            mfa_required=True,
            mfa_challenge_token=challenge_token,
            mfa_methods=["totp", "backup_code"],
        )
    eff_perms = list(policy_registry.resolve_effective_permissions(token_roles))
    await _check_device_trust(user_id, request)
    await lifecycle_service.record_login_attempt(
        user_id,
        req.provider,
        ip_addr,
        user_agent,
        "success",
        suspicious=suspicious,
        details=reason,
    )
    access_token, refresh_token, exp = issue_jwt(
        user_id=user_id,
        email=profile.email,
        roles=token_roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
    )
    await _register_refresh_token(refresh_token)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=exp,
        user_id=user_id,
        email=profile.email,
        roles=token_roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
        mfa_verified=True,
    )
# SAML ACS Route
@app.get("/api/v1/auth/saml/{org_id}/start")
async def saml_login_start(org_id: str):
    cfg = await enterprise_service.get_idp_config(org_id)
    if not cfg or cfg.sso_type != "saml" or not cfg.metadata_xml:
        raise HTTPException(
            status_code=400, detail="SAML is not configured for this organization"
        )
    adapter = SAML2Adapter(
        sp_entity_id=_settings.auth.saml_sp_entity_id,
        acs_url=_settings.auth.saml_acs_url,
        idp_metadata_xml=cfg.metadata_xml,
        idp_issuer=cfg.issuer_url,
    )
    relay = secrets.token_urlsafe(32)
    try:
        auth_url, request_id = adapter.build_authn_request(relay)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    r = await get_redis_client()
    if r is None:
        raise HTTPException(
            status_code=503, detail="SAML transaction storage unavailable"
        )
    record = json.dumps({"org_id": org_id, "request_id": request_id})
    if not await r.set(f"saml_relay:{digest(relay)}", record, ex=600, nx=True):
        raise HTTPException(status_code=503, detail="Unable to store SAML transaction")
    if not await r.set(f"saml_request:{digest(request_id)}", org_id, ex=600, nx=True):
        await r.delete(f"saml_relay:{digest(relay)}")
        raise HTTPException(
            status_code=503, detail="Unable to store SAML request correlation"
        )
    return RedirectResponse(url=auth_url)
from fastapi import Form


@app.post("/api/v1/auth/saml/acs", response_model=TokenResponse)
async def saml_acs(
    request: Request,
    SAMLResponse: str | None = Form(None),
    RelayState: str | None = Form(None),
    req: SAMLACSRequest | None = None,
):
    saml_resp_val = SAMLResponse
    relay_state_val = RelayState
    if not saml_resp_val and req:
        saml_resp_val = req.SAMLResponse
        relay_state_val = req.RelayState
    if not saml_resp_val and request.headers.get("content-type", "").startswith("application/json"):
        try:
            body = await request.json()
            saml_resp_val = body.get("SAMLResponse")
            relay_state_val = body.get("RelayState")
        except Exception:
            pass
    if not saml_resp_val:
        raise HTTPException(status_code=400, detail="Missing required SAMLResponse form parameter or body.")
    req = SAMLACSRequest(SAMLResponse=saml_resp_val, RelayState=relay_state_val)
    r = await get_redis_client()
    if r is None or not req.RelayState:
        raise HTTPException(
            status_code=503, detail="SAML transaction validation unavailable"
        )
    relay_raw = await r.getdel(f"saml_relay:{digest(req.RelayState)}")
    try:
        relay_record = json.loads(relay_raw) if relay_raw else {}
    except ValueError:
        relay_record = {}
    org_id = relay_record.get("org_id")
    expected_request_id = relay_record.get("request_id")
    if not org_id or not expected_request_id:
        raise HTTPException(
            status_code=401, detail="Invalid or expired SAML RelayState"
        )
    idp_config = await enterprise_service.get_idp_config(org_id)
    if not idp_config or idp_config.sso_type != "saml":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"SAML SSO is not configured for organization '{org_id}'.",
        )
    adapter = SAML2Adapter(
        sp_entity_id=_settings.auth.saml_sp_entity_id,
        acs_url=_settings.auth.saml_acs_url,
        idp_metadata_xml=idp_config.metadata_xml,
        idp_issuer=idp_config.issuer_url,
    )
    try:
        claims = await adapter.parse_saml_response(
            req.SAMLResponse, expected_in_response_to=expected_request_id
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"SAML assertion validation failed: {exc}",
        )
    consumed_request = await r.getdel(f"saml_request:{digest(expected_request_id)}")
    if consumed_request != org_id:
        raise HTTPException(
            status_code=401, detail="SAML AuthnRequest already consumed or mismatched"
        )
    response_id = claims.get("response_id")
    if not response_id:
        raise HTTPException(
            status_code=401,
            detail="SAML Response ID missing.",
        )
    if not await r.set(f"saml_replay:{digest(response_id)}", "1", ex=600, nx=True):
        raise HTTPException(status_code=401, detail="SAML response replay detected.")
    await _check_domain_sso_policy(claims["email"], method="saml")
    configured_domains = {
        d.lower().strip().lstrip("@") for d in idp_config.allowed_domains
    }
    email_domain = claims["email"].rsplit("@", 1)[-1].lower()
    if configured_domains and email_domain not in configured_domains:
        raise HTTPException(
            status_code=403,
            detail="SAML identity email domain is not allowed for this organization.",
        )
    profile = await lifecycle_service.get_or_create_profile(
        email=claims["email"],
        auth_provider="saml",
        display_name=claims.get("name"),
        provider_sub=claims["sub"],
        issuer=claims["issuer"],
    )
    assert_login_allowed(profile)
    assert_admin_mfa_enrolled(profile)
    if profile.org_id and profile.org_id != org_id:
        raise HTTPException(status_code=403, detail="User organization scope mismatch")
    profile.org_id = org_id
    mapped_roles = await enterprise_service.map_idp_groups_to_roles(
        org_id, claims.get("groups", [])
    )
    token_roles = sorted(set(profile.roles + mapped_roles))
    profile.updated_at = datetime.now(UTC).isoformat()
    await db_upsert_user_profile(profile.model_dump())
    user_id = profile.user_id
    ip_addr = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "unknown")
    suspicious, reason = assess_suspicious_login(
        user_id,
        ip_addr,
        user_agent,
        [h.model_dump() for h in await lifecycle_service.get_login_history(user_id)],
    )
    if profile.mfa_enabled or suspicious:
        challenge_token = await store_mfa_login_challenge(
            user_id=user_id,
            email=profile.email,
            tenant_id=profile.tenant_id,
            org_id=profile.org_id,
            roles=token_roles,
            ttl=300,
        )
        return TokenResponse(
            access_token="",
            refresh_token="",
            expires_in=300,
            user_id=user_id,
            email=profile.email,
            roles=token_roles,
            permissions=[],
            tenant_id=profile.tenant_id,
            org_id=profile.org_id,
            mfa_verified=False,
            mfa_required=True,
            mfa_challenge_token=challenge_token,
            mfa_methods=["totp", "backup_code"],
        )
    eff_perms = list(policy_registry.resolve_effective_permissions(token_roles))
    await _check_device_trust(user_id, request)
    await lifecycle_service.record_login_attempt(
        user_id,
        "saml",
        ip_addr,
        user_agent,
        "success",
        suspicious=suspicious,
        details=reason,
    )
    access_token, refresh_token, exp = issue_jwt(
        user_id=user_id,
        email=profile.email,
        roles=token_roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
    )
    await _register_refresh_token(refresh_token)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=exp,
        user_id=user_id,
        email=profile.email,
        roles=token_roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
        mfa_verified=True,
    )
# Token Refresh
@app.post("/api/v1/auth/refresh", response_model=TokenResponse)
async def refresh_tokens(req: TokenRefreshRequest):
    try:
        claims = decode_refresh_token(req.refresh_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token.")
    if claims.get("token_use") != "refresh":
        raise HTTPException(status_code=401, detail="Refresh token required.")
    uid, sid, jti = claims.get("sub"), claims.get("sid"), claims.get("jti")
    if not uid or not sid or not jti:
        raise HTTPException(status_code=401, detail="Invalid refresh token claims.")
    consumed = await refresh_consume(jti, uid, sid)
    if not consumed:
        r = await get_redis_client()
        if r is None:
            raise HTTPException(
                status_code=503, detail="Refresh replay protection unavailable"
            )
        await r.set(
            f"revoked:sid:{sid}",
            "true",
            ex=max(60, int(claims.get("exp", 0)) - int(time.time())),
        )
        raise HTTPException(
            status_code=401, detail="Refresh token replay detected; session revoked."
        )
    profile = await lifecycle_service.get_profile(uid)
    if not profile:
        raise HTTPException(status_code=401, detail="Account unavailable.")
    assert_login_allowed(profile)
    assert_admin_mfa_enrolled(profile)
    r = await get_redis_client()
    if r is None:
        raise HTTPException(status_code=503, detail="Session validation unavailable.")
    cutoff = await r.get(f"tokens_valid_after:{uid}")
    if cutoff and int(claims.get("iat", 0)) <= float(cutoff):
        raise HTTPException(status_code=401, detail="Refresh token revoked.")
    if await r.get(f"revoked:sid:{sid}"):
        raise HTTPException(status_code=401, detail="Session revoked.")
    permissions = list(policy_registry.resolve_effective_permissions(profile.roles))
    access, new_refresh, exp = issue_jwt(
        user_id=uid,
        email=profile.email,
        roles=profile.roles,
        permissions=permissions,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
        session_id=sid,
    )
    await _register_refresh_token(new_refresh)
    return TokenResponse(
        access_token=access,
        refresh_token=new_refresh,
        expires_in=exp,
        user_id=uid,
        email=profile.email,
        roles=profile.roles,
        permissions=permissions,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
    )
# Organization Invitations
@app.post("/api/v1/orgs/{org_id}/invitations", response_model=InvitationResponse)
async def create_invitation_route(
    org_id: str, req: InvitationCreateRequest, user: CurrentUserDep
):
    _require_org_scope(user, org_id, "org:manage")
    return await lifecycle_service.create_invitation(
        req.email, org_id, req.role, user.user_id, req.expires_in_days
    )
@app.get("/api/v1/invitations/{token}")
async def get_invitation_route(token: str):
    inv = await lifecycle_service.get_invitation(token)
    if not inv:
        raise HTTPException(
            status_code=404, detail="Invitation token not found or expired"
        )
    return inv
@app.post("/api/v1/invitations/accept", response_model=UserProfile)
async def accept_invitation_route(req: InvitationAcceptRequest):
    try:
        return await lifecycle_service.accept_invitation(
            req.token, req.password, req.display_name
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
# Account Grace Period Soft-Deletion
@app.post("/api/v1/users/me/delete-account")
async def delete_my_account(user: CurrentUserDep, reauth: ReauthDep):
    await lifecycle_service.schedule_account_deletion(
        user.user_id, grace_period_days=30
    )
    return {
        "status": "pending_deletion",
        "detail": "Account scheduled for deletion after 30-day grace period.",
    }
@app.post("/api/v1/users/me/cancel-deletion", response_model=UserProfile)
async def cancel_my_account_deletion(user: CurrentUserDep):
    try:
        return await lifecycle_service.cancel_account_deletion(user.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
# Active Organization Switching
@app.get("/api/v1/users/me/orgs")
async def list_my_orgs(user: CurrentUserDep):
    return await db_get_user_org_memberships(user.user_id)
@app.post("/api/v1/users/me/switch-org", response_model=TokenResponse)
async def switch_active_org(req: SwitchOrgRequest, user: CurrentUserDep):
    memberships = await db_get_user_org_memberships(user.user_id)
    target_mem = next((m for m in memberships if m["org_id"] == req.org_id), None)
    if not target_mem and not user.has_permission("platform:admin"):
        raise HTTPException(
            status_code=403, detail="Not a member of target organization"
        )
    profile = await lifecycle_service.get_profile(user.user_id)
    if not profile:
        raise HTTPException(status_code=404, detail="User profile not found")
    profile.org_id = req.org_id
    if target_mem and target_mem["role"] not in profile.roles:
        profile.roles.append(target_mem["role"])
    profile.updated_at = datetime.now(UTC).isoformat()
    await db_upsert_user_profile(profile.model_dump())
    eff_perms = list(policy_registry.resolve_effective_permissions(profile.roles))
    access_token, refresh_token, exp = issue_jwt(
        user_id=user.user_id,
        email=profile.email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=req.org_id,
    )
    await _register_refresh_token(refresh_token)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=exp,
        user_id=user.user_id,
        email=profile.email,
        roles=profile.roles,
        permissions=eff_perms,
        tenant_id=profile.tenant_id,
        org_id=req.org_id,
    )
# Security Events & Login History
@app.get("/api/v1/users/me/security-events")
async def get_security_events(user: CurrentUserDep):
    history = await lifecycle_service.get_login_history(user.user_id, limit=50)
    return [
        SecurityEventResponse(
            id=h.id,
            user_id=h.user_id,
            timestamp=h.timestamp,
            provider=h.provider,
            ip_address=h.ip_address,
            user_agent=h.user_agent,
            suspicious=h.suspicious,
            details=h.details,
        )
        for h in history
    ]
# Token Revocation
@app.post("/api/v1/auth/revoke")
async def revoke_token(req: TokenRevokeRequest, user: CurrentUserDep):
    try:
        claims = decode_signed_token(req.token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token for revocation.")
    if claims.get("sub") != user.user_id:
        raise HTTPException(
            status_code=403, detail="Cannot revoke another user's token."
        )
    r = await get_redis_client()
    if r is None:
        raise HTTPException(status_code=503, detail="Revocation state unavailable.")
    jti, sid = claims.get("jti"), claims.get("sid")
    if jti:
        await r.setex(
            f"revoked:{jti}", max(60, int(claims["exp"]) - int(time.time())), "true"
        )
    if sid:
        await r.setex(
            f"revoked:sid:{sid}", max(60, int(claims["exp"]) - int(time.time())), "true"
        )
    return {"status": "revoked"}
@app.post("/api/v1/users/me/sessions/revoke")
async def revoke_bff_session(req: SessionRevokeRequest, user: CurrentUserDep):
    r = await get_redis_client()
    if r is None:
        raise HTTPException(status_code=503, detail="Session revocation unavailable")
    session_key = f"session:{user.tenant_id}:{req.session_id}"
    session = await r.hgetall(session_key)
    if not session or session.get("user_id") != user.user_id:
        raise HTTPException(status_code=404, detail="Session not found")
    token = session.get("jwt")
    if token:
        try:
            claims = decode_signed_token_allow_expired(token)
        except Exception as exc:
            raise HTTPException(
                status_code=401, detail="Stored session token invalid"
            ) from exc
        if claims.get("sub") != user.user_id:
            raise HTTPException(status_code=404, detail="Session not found")
        ttl = max(60, int(claims.get("exp", 0)) - int(time.time()))
        if claims.get("sid"):
            await r.set(f"revoked:sid:{claims['sid']}", "true", ex=ttl)
        if claims.get("jti"):
            await r.set(f"revoked:{claims['jti']}", "true", ex=ttl)
    await r.delete(session_key)
    await r.srem(f"user_sessions:{user.tenant_id}:{user.user_id}", req.session_id)
    return {"status": "revoked", "session_id": req.session_id}
@app.post("/api/v1/users/me/logout-all")
async def revoke_all_sessions(user: CurrentUserDep):
    r = await get_redis_client()
    if r is None:
        raise HTTPException(status_code=503, detail="Session revocation unavailable")
    await r.set(f"tokens_valid_after:{user.user_id}", str(time.time()))
    index_key = f"user_sessions:{user.tenant_id}:{user.user_id}"
    session_ids = await r.smembers(index_key)
    for session_id in session_ids:
        session_key = f"session:{user.tenant_id}:{session_id}"
        session = await r.hgetall(session_key)
        if session.get("jwt"):
            try:
                claims = decode_signed_token_allow_expired(session["jwt"])
            except Exception:
                claims = {}
            ttl = max(60, int(claims.get("exp", 0)) - int(time.time()))
            if claims.get("sid"):
                await r.set(f"revoked:sid:{claims['sid']}", "true", ex=ttl)
            if claims.get("jti"):
                await r.set(f"revoked:{claims['jti']}", "true", ex=ttl)
        await r.delete(session_key)
    await r.delete(index_key)
    return {"status": "logged_out_all", "count": len(session_ids)}
# Password Recovery & Magic Links
@app.post("/api/v1/auth/magic-link")
async def request_magic_link(req: MagicLinkRequest):
    await _check_domain_sso_policy(req.email.lower().strip(), method="magic_link")
    r = await get_redis_client()
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    if r is None:
        raise HTTPException(
            status_code=503, detail="Passwordless authentication is unavailable."
        )
    rate_key = f"magic_rate:{digest(req.email.lower().strip())}"
    rate_count = await r.incr(rate_key)
    if rate_count == 1:
        await r.expire(rate_key, 3600)
    if rate_count > 5:
        raise HTTPException(
            status_code=429, detail="Too many passwordless requests. Try later."
        )
    existing = await db_get_user_by_email(req.email.lower().strip())
    if existing:
        await r.setex(f"magic:{token_hash}", 900, existing["email"])
    await get_mailer().send_magic_link(
        req.email, f"/auth/magic-verify?token={raw_token}"
    )
    return {
        "status": "accepted",
        "detail": "If the email is valid, a login link has been dispatched.",
    }
@app.post("/api/v1/auth/magic-link/verify", response_model=TokenResponse)
async def verify_magic_link(req: MagicLinkVerifyRequest, request: Request):
    token_hash = hashlib.sha256(req.token.encode("utf-8")).hexdigest()
    r = await get_redis_client()
    if r is None:
        raise HTTPException(
            status_code=503, detail="Passwordless token validation unavailable."
        )
    email = await r.getdel(f"magic:{token_hash}")
    if not email:
        raise HTTPException(status_code=401, detail="Invalid or expired magic link.")
    profile_data = await db_get_user_by_email(email)
    if not profile_data:
        raise HTTPException(status_code=401, detail="Account unavailable.")
    profile = await lifecycle_service.get_profile(profile_data["user_id"])
    if not profile or not profile.email_verified:
        raise HTTPException(status_code=401, detail="Email verification required.")
    assert_login_allowed(profile)
    assert_admin_mfa_enrolled(profile)
    if profile.mfa_enabled:
        challenge_token = await store_mfa_login_challenge(
            user_id=profile.user_id,
            email=profile.email,
            tenant_id=profile.tenant_id,
            org_id=profile.org_id,
            roles=profile.roles,
            ttl=300,
        )
        return TokenResponse(
            access_token="",
            refresh_token="",
            expires_in=300,
            user_id=profile.user_id,
            email=profile.email,
            roles=profile.roles,
            permissions=[],
            tenant_id=profile.tenant_id,
            org_id=profile.org_id,
            mfa_verified=False,
            mfa_required=True,
            mfa_challenge_token=challenge_token,
            mfa_methods=["totp", "backup_code"],
        )
    await _check_device_trust(profile.user_id, request)
    permissions = list(policy_registry.resolve_effective_permissions(profile.roles))
    access_token, refresh_token, exp = issue_jwt(
        user_id=profile.user_id,
        email=profile.email,
        roles=profile.roles,
        permissions=permissions,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
    )
    await _register_refresh_token(refresh_token)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=exp,
        user_id=profile.user_id,
        email=profile.email,
        roles=profile.roles,
        permissions=permissions,
        tenant_id=profile.tenant_id,
        org_id=profile.org_id,
        mfa_verified=True,
    )
@app.post("/api/v1/users/recovery", status_code=202)
async def request_account_recovery(req: AccountRecoveryRequest):
    await _check_domain_sso_policy(req.email.lower().strip(), method="recovery")
    r = await get_redis_client()
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    if r is None:
        raise HTTPException(status_code=503, detail="Account recovery is unavailable.")
    limit_key = f"recovery_rate:{digest(req.email.lower().strip())}"
    attempts = await r.incr(limit_key)
    if attempts == 1:
        await r.expire(limit_key, 3600)
    if attempts > 5:
        raise HTTPException(
            status_code=429, detail="Too many recovery requests. Try later."
        )
    existing = await db_get_user_by_email(req.email.lower().strip())
    if existing:
        await r.setex(f"recovery:{token_hash}", 1800, existing["email"])
    await get_mailer().send_account_recovery(
        req.email, f"/auth/recovery?token={raw_token}"
    )
    return {
        "status": "accepted",
        "detail": "If an account exists for this email, password recovery instructions have been sent.",
    }
@app.post("/api/v1/users/recovery/confirm")
async def confirm_account_recovery(req: AccountRecoveryConfirmRequest):
    if len(req.new_password) < _settings.auth.min_password_length:
        raise HTTPException(
            status_code=400,
            detail=f"Password must be at least {_settings.auth.min_password_length} characters.",
        )
    r = await get_redis_client()
    token_hash = hashlib.sha256(req.token.encode("utf-8")).hexdigest()
    email = await r.getdel(f"recovery:{token_hash}") if r else None
    if not email:
        raise HTTPException(
            status_code=400, detail="Invalid or expired account recovery token."
        )
    existing = await db_get_user_by_email(email)
    if not existing:
        raise HTTPException(
            status_code=400, detail="Invalid or expired account recovery token."
        )
    profile = await lifecycle_service.get_profile(existing["user_id"])
    if not profile:
        raise HTTPException(
            status_code=400, detail="Invalid or expired account recovery token."
        )
    user_id = profile.user_id
    new_hash = await async_hash_password(req.new_password)
    await db_save_user_password(user_id, new_hash)
    await lifecycle_service.logout_all_devices(user_id)
    return {"status": "success", "detail": "Password successfully updated."}
@app.post("/api/v1/users/verify-email/request", status_code=202)
async def request_email_verification(user: CurrentUserDep):
    r = await get_redis_client()
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    if r is None:
        raise HTTPException(status_code=503, detail="Email verification unavailable.")
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
    profile.updated_at = datetime.now(UTC).isoformat()
    await db_upsert_user_profile(profile.model_dump())
    return {"status": "success", "detail": "Email verified successfully."}
# ---------------------------------------------------------------------------
# Reauthentication / Step-Up Sudo Tokens
# ---------------------------------------------------------------------------
@app.post("/api/v1/users/me/device-trust")
async def device_trust_route(
    req: DeviceTrustRequest, user: CurrentUserDep, reauth: ReauthDep, request: Request
):
    if not _settings.auth.enforce_device_trust:
        raise HTTPException(
            status_code=400, detail="Device trust policy is not enabled"
        )
    expected = compute_device_fingerprint(
        request.headers.get("User-Agent", "unknown"),
        request.client.host if request.client else "0.0.0.0",
    )
    if not secrets.compare_digest(expected, req.device_fingerprint):
        raise HTTPException(
            status_code=400, detail="Fingerprint does not match current device"
        )
    r = await get_redis_client()
    if r is None:
        raise HTTPException(status_code=503, detail="Device trust storage unavailable")
    if req.trust_device:
        await r.set(f"trusted_device:{user.user_id}:{expected}", "1", ex=30 * 86400)
    else:
        await r.delete(f"trusted_device:{user.user_id}:{expected}")
    return {
        "status": "trusted" if req.trust_device else "revoked",
        "fingerprint": expected,
    }
@app.post("/api/v1/users/me/mfa/enroll", response_model=TOTPSetupResponse)
async def mfa_enroll(user: CurrentUserDep):
    secret = generate_totp_secret()
    await store_mfa_secret(user.user_id, secret, ttl=600)
    uri = get_totp_uri(secret, user.email)
    return TOTPSetupResponse(
        secret=secret, otpauth_url=uri, qr_code_payload=uri, backup_codes=[]
    )
@app.post("/api/v1/users/me/mfa/verify")
async def mfa_verify_enrollment(req: TOTPVerifyRequest, user: CurrentUserDep):
    secret = await consume_mfa_enrollment(user.user_id)
    if not secret or not verify_totp_code(secret, req.code):
        raise HTTPException(
            status_code=400, detail="Invalid or expired MFA enrollment."
        )
    await save_mfa_secret(user.user_id, secret)
    backup_codes = [secrets.token_urlsafe(10) for _ in range(10)]
    await save_backup_codes(user.user_id, backup_codes)
    profile = await lifecycle_service.get_profile(user.user_id)
    if not profile:
        await delete_mfa_secret(user.user_id)
        raise HTTPException(status_code=404, detail="Profile not found")
    profile.mfa_enabled = True
    profile.updated_at = datetime.now(UTC).isoformat()
    await db_upsert_user_profile(profile.model_dump())
    return {"status": "enabled", "backup_codes": backup_codes}
@app.post("/api/v1/users/me/mfa/disable")
async def mfa_disable(req: TOTPVerifyRequest, user: CurrentUserDep, reauth: ReauthDep):
    secret = await get_mfa_secret(user.user_id)
    if not secret or not verify_totp_code(secret, req.code):
        raise HTTPException(status_code=401, detail="MFA verification failed")
    profile = await lifecycle_service.get_profile(user.user_id)
    if profile:
        profile.mfa_enabled = False
        profile.updated_at = datetime.now(UTC).isoformat()
        await db_upsert_user_profile(profile.model_dump())
    await delete_mfa_secret(user.user_id)
    return {"status": "disabled"}
@app.post("/api/v1/auth/reauthenticate", response_model=ReauthResponse)
async def reauthenticate(req: ReauthRequest, user: CurrentUserDep):
    proof = False
    if req.password:
        stored = await db_get_user_password(user.user_id)
        if not stored or not verify_password(req.password, stored):
            raise HTTPException(
                status_code=401, detail="Password proof failed or unavailable."
            )
        proof = True
    if req.mfa_code:
        secret = await get_mfa_secret(user.user_id)
        if not secret or not verify_totp_code(secret, req.mfa_code):
            if not await consume_backup_code(user.user_id, req.mfa_code):
                raise HTTPException(status_code=401, detail="MFA proof failed.")
        proof = True
    if not proof:
        raise HTTPException(
            status_code=400, detail="Password or MFA proof is required."
        )
    sudo_token = issue_sudo_token(user.user_id)
    await put_once(
        f"sudo_token:{digest(sudo_token)}",
        {"user_id": user.user_id, "sid": user.session_id, "action": req.action},
        300,
    )
    return ReauthResponse(sudo_token=sudo_token, expires_in=300)
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
async def delete_my_account_by_delete(user: CurrentUserDep, reauth: ReauthDep):
    await lifecycle_service.schedule_account_deletion(
        user.user_id, grace_period_days=30
    )
    return {
        "status": "pending_deletion",
        "detail": "Account scheduled for deletion after 30-day grace period.",
    }
@app.get("/api/v1/users/me/login-history")
async def get_my_login_history(user: CurrentUserDep):
    return await lifecycle_service.get_login_history(user.user_id)
# ---------------------------------------------------------------------------
# Provider Linking & Unlinking Routes
# ---------------------------------------------------------------------------
@app.get("/api/v1/users/me/providers/{provider}/link/authorize-url")
async def provider_link_authorize_url(
    provider: str, redirect_uri: str, user: CurrentUserDep
):
    if provider not in {"google", "entra", "github", "generic_oidc"}:
        raise HTTPException(status_code=400, detail="Unsupported provider")
    if provider in ("generic_oidc", "entra"):
        if not user.org_id:
            raise HTTPException(
                status_code=400,
                detail="Organization IdP configuration is required for this provider",
            )
        cfg = await enterprise_service.get_idp_config_raw(user.org_id)
        if not cfg or cfg.get("sso_type") != "oidc" or not cfg.get("client_secret"):
            raise HTTPException(
                status_code=400, detail="Organization OIDC configuration unavailable"
            )
        if provider == "entra":
            issuer_url = cfg.get("issuer_url", "")
            tenant_id = (
                issuer_url.rstrip("/").split("/")[-2]
                if issuer_url.rstrip("/").endswith("/v2.0")
                else issuer_url.rstrip("/").split("/")[-1]
            )
            adapter = MicrosoftEntraAdapter(
                cfg["client_id"], cfg["client_secret"], tenant_id=tenant_id
            )
        else:
            adapter = GenericOIDCAdapter(
                cfg["issuer_url"], cfg["client_id"], cfg["client_secret"]
            )
    else:
        adapter = provider_registry.get_adapter(provider)
    transaction = await oauth_begin(
        provider,
        redirect_uri,
        user.tenant_id,
        user.org_id,
        purpose="link",
        user_id=user.user_id,
    )
    url = await adapter.get_auth_url(
        transaction["state"],
        redirect_uri,
        transaction["challenge"],
        transaction["nonce"],
    )
    return {"authorization_url": url, "state": transaction["state"]}
@app.post("/api/v1/users/me/providers/link", response_model=UserProfile)
async def link_provider_route(
    req: LinkProviderRequest, user: CurrentUserDep, reauth: ReauthDep
):
    tx = await oauth_consume(req.state, req.provider)
    if (
        tx.get("purpose") != "link"
        or tx.get("user_id") != user.user_id
        or tx.get("redirect_uri") != req.redirect_uri
    ):
        raise HTTPException(
            status_code=401, detail="Provider-link transaction binding mismatch"
        )
    if req.provider in ("generic_oidc", "entra") and tx.get("org_id"):
        cfg = await enterprise_service.get_idp_config_raw(tx["org_id"])
        if not cfg or not cfg.get("client_secret"):
            raise HTTPException(
                status_code=400, detail="Organization OIDC configuration unavailable"
            )
        if req.provider == "entra":
            issuer_url = cfg.get("issuer_url", "")
            tenant_id = (
                issuer_url.rstrip("/").split("/")[-2]
                if issuer_url.rstrip("/").endswith("/v2.0")
                else issuer_url.rstrip("/").split("/")[-1]
            )
            adapter = MicrosoftEntraAdapter(
                cfg["client_id"], cfg["client_secret"], tenant_id=tenant_id
            )
        else:
            adapter = GenericOIDCAdapter(
                cfg["issuer_url"], cfg["client_id"], cfg["client_secret"]
            )
    else:
        adapter = provider_registry.get_adapter(req.provider)
    identity = await adapter.exchange_code(
        req.code, req.redirect_uri, tx.get("verifier"), tx.get("nonce")
    )
    if req.provider != "github" and identity.get("raw_claims", {}).get(
        "nonce"
    ) != tx.get("nonce"):
        raise HTTPException(status_code=401, detail="OIDC nonce validation failed")
    if (
        not identity.get("sub")
        or not identity.get("email")
        or not identity.get("email_verified")
    ):
        raise HTTPException(
            status_code=401,
            detail="Provider returned incomplete or unverified identity proof",
        )
    existing = await db_get_federated_identity(
        req.provider, identity.get("issuer") or req.provider, str(identity["sub"])
    )
    if existing and existing.get("user_id") != user.user_id:
        raise HTTPException(
            status_code=409,
            detail="Provider identity is already linked to another account",
        )
    return await lifecycle_service.link_provider(
        user.user_id,
        req.provider,
        str(identity["sub"]),
        email=identity["email"],
        issuer=identity.get("issuer"),
    )
@app.delete("/api/v1/users/me/providers/{provider}", response_model=UserProfile)
async def unlink_provider_route(provider: str, user: CurrentUserDep, reauth: ReauthDep):
    try:
        return await lifecycle_service.unlink_provider(user.user_id, provider)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
# ---------------------------------------------------------------------------
# RBAC, Delegations & Trip Sharing
# ---------------------------------------------------------------------------
@app.get("/api/v1/rbac/roles")
async def list_rbac_roles(user: CurrentUserDep):
    if not user.has_permission("rbac:read") and not user.has_permission("org:manage"):
        raise HTTPException(status_code=403, detail="RBAC catalog access denied")
    return ROLES_CATALOG
@app.post("/api/v1/rbac/roles/assign")
async def assign_role_route(req: RoleAssignmentRequest, user: CurrentUserDep):
    if not user.has_permission("users:manage") and not user.has_permission(
        "org:manage"
    ):
        raise HTTPException(status_code=403, detail="Role assignment permission denied")
    if req.role not in ROLES_CATALOG:
        raise HTTPException(status_code=400, detail="Unknown role")
    target = await lifecycle_service.get_profile(req.user_id)
    if not target or target.tenant_id != req.tenant_id:
        raise HTTPException(status_code=404, detail="User not found in tenant")
    role_scope = ROLES_CATALOG[req.role].scope
    if role_scope == "resource":
        raise HTTPException(
            status_code=400,
            detail="Resource-scoped roles must be assigned through resource policy, not global user roles",
        )
    r = await get_redis_client()
    if r is None:
        raise HTTPException(status_code=503, detail="Token invalidation unavailable")
    if role_scope == "platform" and not user.has_permission("platform:admin"):
        raise HTTPException(
            status_code=403, detail="Platform roles require platform administrator"
        )
    if role_scope == "organization":
        if (
            not req.org_id
            or req.org_id != user.org_id
            and not user.has_permission("platform:admin")
        ):
            raise HTTPException(
                status_code=403, detail="Organization role assignment scope denied"
            )
        if target.org_id and target.org_id != req.org_id:
            raise HTTPException(
                status_code=403,
                detail="Target user belongs to a different organization",
            )
        target.org_id = req.org_id
    scope_id = (
        req.org_id
        if role_scope == "organization"
        else req.tenant_id
        if role_scope == "tenant"
        else None
    )
    await db_assign_role(req.user_id, req.role, role_scope, scope_id, user.user_id)
    if req.role not in target.roles:
        target.roles.append(req.role)
    target.updated_at = datetime.now(UTC).isoformat()
    await db_upsert_user_profile(target.model_dump())
    await r.set(f"tokens_valid_after:{target.user_id}", str(time.time()))
    return {
        "status": "assigned",
        "role": req.role,
        "scope": role_scope,
        "scope_id": scope_id,
    }
@app.post("/api/v1/rbac/roles/revoke")
async def revoke_role_route(req: RoleRevocationRequest, user: CurrentUserDep):
    if not user.has_permission("users:manage") and not user.has_permission(
        "org:manage"
    ):
        raise HTTPException(status_code=403, detail="Role revocation permission denied")
    if req.role not in ROLES_CATALOG:
        raise HTTPException(status_code=400, detail="Unknown role")
    target = await lifecycle_service.get_profile(req.user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    scope = ROLES_CATALOG[req.role].scope
    if scope == "resource":
        raise HTTPException(
            status_code=400,
            detail="Resource-scoped role revocation is not a global role operation",
        )
    r = await get_redis_client()
    if r is None:
        raise HTTPException(status_code=503, detail="Token invalidation unavailable")
    if scope == "platform" and not user.has_permission("platform:admin"):
        raise HTTPException(
            status_code=403,
            detail="Platform role revocation requires platform administrator",
        )
    if scope == "organization" and (
        not req.org_id
        or req.org_id != user.org_id
        and not user.has_permission("platform:admin")
    ):
        raise HTTPException(status_code=403, detail="Organization scope denied")
    scope_id = (
        req.org_id
        if scope == "organization"
        else target.tenant_id
        if scope == "tenant"
        else None
    )
    count = await db_revoke_role(req.user_id, req.role, scope, scope_id)
    if count:
        target.roles = [r for r in target.roles if r != req.role]
        if not target.roles:
            target.roles = ["member"]
        target.updated_at = datetime.now(UTC).isoformat()
        await db_upsert_user_profile(target.model_dump())
        await r.set(f"tokens_valid_after:{target.user_id}", str(time.time()))
    return {"status": "revoked" if count else "not_found", "role": req.role}
@app.post("/api/v1/rbac/delegations")
async def create_delegated_permission_route(
    req: DelegatedPermissionRequest, user: CurrentUserDep
):
    if not user.has_permission("trips:share") and not user.has_permission(
        "trips:manage"
    ):
        raise HTTPException(status_code=403, detail="Delegation permission denied")
    if req.resource_type != "trip":
        raise HTTPException(
            status_code=400, detail="Only trip delegations are supported"
        )
    trip = await get_trip_by_id(req.resource_id, tenant_id=user.tenant_id)
    if not trip or trip.get("user_id") != user.user_id:
        raise HTTPException(
            status_code=404, detail="Trip not found or ownership denied"
        )
    delegate = await lifecycle_service.get_profile(req.delegate_user_id)
    if not delegate or delegate.tenant_id != user.tenant_id:
        raise HTTPException(
            status_code=404, detail="Delegate must belong to the same tenant"
        )
    try:
        expiry = datetime.fromisoformat(req.expires_at)
        if expiry <= datetime.now(UTC):
            raise ValueError("Delegation expiry must be in the future")
    except ValueError:
        raise HTTPException(
            status_code=400, detail="Invalid or expired delegation timestamp"
        )
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
    if not user.has_permission("trips:share") and not user.has_permission(
        "trips:manage"
    ):
        raise HTTPException(status_code=403, detail="Trip sharing permission denied")
    trip = await get_trip_by_id(req.trip_id, tenant_id=user.tenant_id)
    if not trip or trip.get("user_id") != user.user_id:
        raise HTTPException(
            status_code=404, detail="Trip not found or ownership denied"
        )
    grantee = await lifecycle_service.get_profile(req.grantee_id)
    if not grantee or grantee.tenant_id != user.tenant_id:
        raise HTTPException(
            status_code=404, detail="Grantee must belong to the same tenant"
        )
    if req.permission_level not in {"read", "write", "admin"}:
        raise HTTPException(status_code=400, detail="Invalid trip share permission")
    if req.expires_at:
        try:
            share_expiry = datetime.fromisoformat(req.expires_at)
            if share_expiry <= datetime.now(UTC):
                raise ValueError
        except ValueError:
            raise HTTPException(
                status_code=400, detail="Share expiry must be a future timestamp"
            )
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
    _require_org_scope(user, org_id, "sso:read")
    cfg = await enterprise_service.get_idp_config(org_id)
    if not cfg:
        raise HTTPException(status_code=404, detail="IdP Config not found.")
    return cfg
@app.post("/api/v1/orgs/{org_id}/idp-config", response_model=IdPConfigResponse)
async def set_idp_config_route(
    org_id: str, req: IdPConfigRequest, user: CurrentUserDep, reauth: ReauthDep
):
    _require_org_scope(user, org_id, "sso:manage")
    req.org_id = org_id
    return await enterprise_service.set_idp_config(req)
@app.post("/api/v1/orgs/{org_id}/scim-tokens")
async def issue_org_scim_token(org_id: str, user: CurrentUserDep, reauth: ReauthDep):
    _require_org_scope(user, org_id, "scim:manage")
    raw_token = f"scim_{secrets.token_urlsafe(32)}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    await db_save_scim_token(org_id, token_hash)
    return {
        "org_id": org_id,
        "token": raw_token,
        "detail": "SCIM Bearer Token created. Store securely as it will not be shown again.",
    }
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
# ---------------------------------------------------------------------------
# SCIM 2.0 Discovery & Service Provider Configuration Endpoints (RFC 7643 / 7644)
# ---------------------------------------------------------------------------
@app.get("/scim/v2/ServiceProviderConfig")
async def scim_service_provider_config():
    return JSONResponse(
        content={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": f"{_settings.auth.public_base_url}/docs/scim",
            "patch": {"supported": True},
            "bulk": {
                "supported": False,
                "maxOperations": 1000,
                "maxPayloadSize": 1048576,
            },
            "filter": {"supported": True, "maxResults": 200},
            "changePassword": {"supported": True},
            "sort": {"supported": True},
            "etag": {"supported": True},
            "authenticationSchemes": [
                {
                    "name": "OAuth Bearer Token",
                    "description": "Authentication scheme using SCIM Bearer Tokens",
                    "specUri": "http://www.rfc-editor.org/info/rfc6750",
                    "type": "oauthbearertoken",
                    "primary": True,
                }
            ],
        },
        headers={"Content-Type": "application/scim+json"},
    )
@app.get("/scim/v2/ResourceTypes")
async def scim_resource_types():
    return JSONResponse(
        content={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 2,
            "Resources": [
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                    "id": "User",
                    "name": "User",
                    "endpoint": "/scim/v2/Users",
                    "description": "User Account Resource",
                    "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
                },
                {
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                    "id": "Group",
                    "name": "Group",
                    "endpoint": "/scim/v2/Groups",
                    "description": "Group Resource",
                    "schema": "urn:ietf:params:scim:schemas:core:2.0:Group",
                },
            ],
        },
        headers={"Content-Type": "application/scim+json"},
    )
@app.get("/scim/v2/Schemas")
async def scim_schemas():
    return JSONResponse(
        content={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": 2,
            "Resources": [
                {
                    "id": "urn:ietf:params:scim:schemas:core:2.0:User",
                    "name": "User",
                    "description": "Core User Schema",
                },
                {
                    "id": "urn:ietf:params:scim:schemas:core:2.0:Group",
                    "name": "Group",
                    "description": "Core Group Schema",
                },
            ],
        },
        headers={"Content-Type": "application/scim+json"},
    )
@app.get("/api/v1/orgs/{org_id}/scim-tokens")
async def list_org_scim_tokens(org_id: str, user: CurrentUserDep):
    if "organization_owner" not in user.roles and "platform_owner" not in user.roles:
        raise HTTPException(
            status_code=403, detail="Insufficient authorization to list SCIM tokens."
        )
    tokens = await db_list_scim_tokens(org_id)
    return {"tokens": tokens}
@app.delete("/api/v1/orgs/{org_id}/scim-tokens/{token_id}")
async def revoke_org_scim_token(
    org_id: str, token_id: str, user: CurrentUserDep, reauth: ReauthDep
):
    if "organization_owner" not in user.roles and "platform_owner" not in user.roles:
        raise HTTPException(
            status_code=403, detail="Insufficient authorization to revoke SCIM tokens."
        )
    deleted = await db_delete_scim_token(token_id, org_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="SCIM token not found.")
    return {"status": "revoked", "token_id": token_id}
@app.get("/scim/v2/Users", response_model=SCIMListResponse)
async def scim_list_users(
    request: Request,
    org_id: str = SCIMAuthDep,
    filter: str | None = None,
    startIndex: int = 1,
    count: int = 100,
    sortBy: str | None = None,
    sortOrder: str = "ascending",
):
    return await scim_service.list_users(
        org_id=org_id,
        filter_query=filter,
        start_index=startIndex,
        count=count,
        sort_by=sortBy,
        sort_order=sortOrder,
    )
@app.post("/scim/v2/Users", response_model=SCIMUserSchema, status_code=201)
async def scim_create_user(
    request: Request, user: SCIMUserSchema, org_id: str = SCIMAuthDep
):
    try:
        return await scim_service.create_user(user, org_id=org_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
@app.get("/scim/v2/Users/{user_id}", response_model=SCIMUserSchema)
async def scim_get_user(request: Request, user_id: str, org_id: str = SCIMAuthDep):
    u = await scim_service.get_user(user_id, org_id=org_id)
    if not u:
        raise HTTPException(status_code=404, detail="SCIM User not found.")
    return u
@app.put("/scim/v2/Users/{user_id}", response_model=SCIMUserSchema)
async def scim_update_user(
    request: Request,
    user_id: str,
    user: SCIMUserSchema,
    org_id: str = SCIMAuthDep,
    if_match: str | None = Header(None, alias="If-Match"),
):
    try:
        return await scim_service.update_user(
            user_id, user, org_id=org_id, if_match=if_match
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=412 if "If-Match" in str(exc) else 400, detail=str(exc)
        )
@app.patch("/scim/v2/Users/{user_id}", response_model=SCIMUserSchema)
async def scim_patch_user(
    request: Request,
    user_id: str,
    patch: SCIMPatchRequest,
    org_id: str = SCIMAuthDep,
    if_match: str | None = Header(None, alias="If-Match"),
):
    try:
        return await scim_service.patch_user(
            user_id, patch.Operations, org_id=org_id, if_match=if_match
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=412 if "If-Match" in str(exc) else 400, detail=str(exc)
        )
@app.delete("/scim/v2/Users/{user_id}", status_code=204)
async def scim_delete_user(
    request: Request,
    user_id: str,
    org_id: str = SCIMAuthDep,
    if_match: str | None = Header(None, alias="If-Match"),
):
    try:
        deleted = await scim_service.delete_user(
            user_id, org_id=org_id, if_match=if_match
        )
        if not deleted:
            raise HTTPException(status_code=404, detail="SCIM User not found.")
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except ValueError as exc:
        raise HTTPException(
            status_code=412 if "If-Match" in str(exc) else 400, detail=str(exc)
        )
@app.get("/scim/v2/Groups", response_model=SCIMListResponse)
async def scim_list_groups(
    request: Request,
    org_id: str = SCIMAuthDep,
    filter: str | None = None,
    startIndex: int = 1,
    count: int = 100,
    sortBy: str | None = None,
    sortOrder: str = "ascending",
):
    return await scim_service.list_groups(
        org_id=org_id,
        filter_query=filter,
        start_index=startIndex,
        count=count,
        sort_by=sortBy,
        sort_order=sortOrder,
    )
@app.post("/scim/v2/Groups", response_model=SCIMGroupSchema, status_code=201)
async def scim_create_group(
    request: Request, group: SCIMGroupSchema, org_id: str = SCIMAuthDep
):
    return await scim_service.create_group(group, org_id=org_id)
@app.get("/scim/v2/Groups/{group_id}", response_model=SCIMGroupSchema)
async def scim_get_group(request: Request, group_id: str, org_id: str = SCIMAuthDep):
    group = await scim_service.get_group(group_id, org_id=org_id)
    if not group:
        raise HTTPException(status_code=404, detail="SCIM Group not found")
    return group
@app.put("/scim/v2/Groups/{group_id}", response_model=SCIMGroupSchema)
async def scim_update_group(
    request: Request,
    group_id: str,
    group: SCIMGroupSchema,
    org_id: str = SCIMAuthDep,
    if_match: str | None = Header(None, alias="If-Match"),
):
    try:
        return await scim_service.update_group(
            group_id, group, org_id=org_id, if_match=if_match
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=412 if "If-Match" in str(exc) else 404, detail=str(exc)
        )
@app.patch("/scim/v2/Groups/{group_id}", response_model=SCIMGroupSchema)
async def scim_patch_group(
    request: Request,
    group_id: str,
    patch: SCIMPatchRequest,
    org_id: str = SCIMAuthDep,
    if_match: str | None = Header(None, alias="If-Match"),
):
    try:
        return await scim_service.patch_group(
            group_id, patch.Operations, org_id=org_id, if_match=if_match
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=412 if "If-Match" in str(exc) else 400, detail=str(exc)
        )
@app.delete("/scim/v2/Groups/{group_id}", status_code=204)
async def scim_delete_group(
    request: Request,
    group_id: str,
    org_id: str = SCIMAuthDep,
    if_match: str | None = Header(None, alias="If-Match"),
):
    try:
        deleted = await scim_service.delete_group(
            group_id, org_id=org_id, if_match=if_match
        )
        if not deleted:
            raise HTTPException(status_code=404, detail="SCIM Group not found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except ValueError as exc:
        raise HTTPException(
            status_code=412 if "If-Match" in str(exc) else 400, detail=str(exc)
        )
@app.get("/api/v1/auth/saml/metadata")
async def saml_sp_metadata_route():
    from services.auth_service.adapters import SAML2Adapter
    adapter = SAML2Adapter()
    metadata_xml = adapter.get_sp_metadata()
    return Response(content=metadata_xml, media_type="application/xml")
@app.post("/api/v1/admin/users/{user_id}/mfa/reset")
async def admin_reset_mfa_route(user_id: str, user: CurrentUserDep, reauth: ReauthDep):
    caller_rank = get_max_caller_rank(user.roles)
    if caller_rank < 60:
        raise HTTPException(
            status_code=403,
            detail="Admin MFA reset requires organization owner or platform administrator privileges.",
        )
    await security_state.delete_mfa_secret(user_id)
    p = await user_lifecycle_service.get_profile(user_id)
    if p:
        p.mfa_enabled = False
        await db_upsert_user_profile(p.model_dump())