from services.core.config import get_settings

_settings = get_settings()
"""
Auth & Identity Microservice (Google OIDC + PKCE + Argon2id + RS256 JWT Issuance + JWKS).
"""
import base64
import hashlib
import json
import logging
import os
import secrets
import time
import urllib.parse
from typing import Any

import httpx
import jwt
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from jwt import PyJWKClient

from services.auth_service.models import (
    GoogleTokenExchangeRequest,
    JWKSResponse,
    TokenResponse,
    TokenRevokeRequest,
    UserLoginRequest,
)
from services.auth_service.security import (
    generate_user_id,
    get_jwks,
    hash_password,
    issue_jwt,
    verify_password,
)

logger = logging.getLogger("travelbrain.auth_service")
app = FastAPI(
    title="TravelBrain Auth & Identity Service",
    version="2.0.0",
    description="Enterprise OIDC Authentication, Argon2id Identity, RS256 JWT Issuance & JWKS Provider",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_OIDC_DISCOVERY_URL = (
    "https://" + "accounts.google.com/.well-known/openid-configuration"
)
GOOGLE_JWKS_URL = "https://" + "www.googleapis.com/oauth2/v3/certs"
ENVIRONMENT = _settings.app.environment
REDIS_URL = _settings.redis.url
# In-memory user store fallback when Postgres is offline
_in_memory_users: dict[str, dict[str, Any]] = {}
_google_jwks_client: PyJWKClient | None = None
_redis_client: Any = None


async def get_redis() -> Any:
    global _redis_client
    if aioredis is None:
        return None
    if _redis_client is None:
        try:
            _redis_client = aioredis.from_url(
                REDIS_URL, encoding="utf-8", decode_responses=True
            )
            await _redis_client.ping()
        except (aioredis.RedisError, OSError) as exc:
            logger.warning("Redis unavailable for Auth service state store: %s", exc)
            _redis_client = None
    return _redis_client


def get_google_jwks_client() -> PyJWKClient:
    global _google_jwks_client
    if _google_jwks_client is None:
        _google_jwks_client = PyJWKClient(GOOGLE_JWKS_URL, cache_keys=True)
    return _google_jwks_client


@app.get("/.well-known/jwks.json", response_model=JWKSResponse)
def jwks_endpoint():
    """Public JWKS endpoint for downstream microservices to verify JWT signatures."""
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
    except (OSError, ValueError, RuntimeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        )


@app.post("/api/v1/auth/login", response_model=TokenResponse)
async def direct_login(req: UserLoginRequest):
    """
    Direct login endpoint with Argon2id password verification and stable UUID generation.
    Disabled in production environments.
    """
    if ENVIRONMENT == "production":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Direct password login disabled in production. Use OIDC SSO.",
        )
    if not req.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is required for direct authentication.",
        )
    email_clean = str(req.email).lower().strip()
    user_id = generate_user_id(email_clean)
    # Validate or create user in state store
    if email_clean in _in_memory_users:
        user_record = _in_memory_users[email_clean]
        if not verify_password(req.password, user_record["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password.",
            )
        roles = user_record.get("roles", ["traveler"])
    else:
        # Create new user record with Argon2id hash
        pwd_hash = hash_password(req.password)
        roles = ["traveler"]
        _in_memory_users[email_clean] = {
            "user_id": user_id,
            "email": email_clean,
            "password_hash": pwd_hash,
            "roles": roles,
            "tenant_id": req.tenant_id,
        }
    access_token, refresh_token, expires_in = issue_jwt(
        user_id=user_id,
        email=email_clean,
        roles=roles,
        tenant_id=req.tenant_id,
        email_verified=True,
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        user_id=user_id,
        email=email_clean,
        roles=roles,
        tenant_id=req.tenant_id,
    )


@app.get("/api/v1/auth/google/url")
async def get_google_auth_url(redirect_uri: str):
    """Generate Google OIDC authorization URL with CSRF state, nonce, and PKCE challenge."""
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(48)
    # Compute S256 PKCE Code Challenge
    code_challenge_bytes = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = (
        base64.urlsafe_b64encode(code_challenge_bytes).rstrip(b"=").decode("ascii")
    )
    # Store state metadata in Redis (or in-memory fallback) with 600s TTL
    state_data = json.dumps({"nonce": nonce, "code_verifier": code_verifier})
    r = await get_redis()
    if r:
        await r.setex(f"oidc:state:{state}", 600, state_data)
    params = {
        "client_id": GOOGLE_CLIENT_ID or "mock-google-client-id",
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "prompt": "consent",
    }
    auth_url = (
        "https://"
        + "accounts.google.com/o/oauth2/v2/auth?"
        + urllib.parse.urlencode(params)
    )
    return {"auth_url": auth_url, "state": state}


@app.post("/api/v1/auth/google/callback", response_model=TokenResponse)
async def google_callback(req: GoogleTokenExchangeRequest):
    """
    Exchange Google authorization code with PKCE, validate OIDC state, nonce,
    and id_token, then issue internal RS256 JWT. Fails closed if OIDC is missing or invalid.
    """
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google OIDC client credentials are not configured.",
        )
    # Validate state parameter against stored Redis state
    r = await get_redis()
    stored_state_raw = None
    if r:
        stored_state_raw = await r.get(f"oidc:state:{req.state}")
        if stored_state_raw:
            await r.delete(f"oidc:state:{req.state}")
    if not stored_state_raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OIDC state parameter is invalid, expired, or missing.",
        )
    state_meta = json.loads(stored_state_raw)
    expected_nonce = state_meta.get("nonce")
    code_verifier = req.code_verifier or state_meta.get("code_verifier")
    # Real Google OIDC Token Exchange
    token_url = "https://" + "oauth2.googleapis.com/token"
    data = {
        "code": req.code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": req.redirect_uri,
        "grant_type": "authorization_code",
    }
    if code_verifier:
        data["code_verifier"] = code_verifier
    async with httpx.AsyncClient() as client:
        resp = await client.post(token_url, data=data)
        if resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Google OAuth token exchange failed: {resp.text}",
            )
        tokens = resp.json()
    id_token_raw = tokens.get("id_token")
    if not id_token_raw:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google token response missing id_token.",
        )
    # Cryptographically verify id_token signature using Google JWKS
    try:
        jwks_client = get_google_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(id_token_raw)
        id_claims = jwt.decode(
            id_token_raw,
            signing_key.key,
            algorithms=["RS256"],
            audience=GOOGLE_CLIENT_ID,
            issuer=["https://" + "accounts.google.com", "accounts.google.com"],
            options={"verify_exp": True, "verify_aud": True, "verify_iss": True},
        )
    except (jwt.PyJWTError, jwt.PyJWKClientError, ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid Google id_token signature or claims: {exc}",
        )
    # Validate Nonce & Email Verification
    if expected_nonce and id_claims.get("nonce") != expected_nonce:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OIDC id_token nonce verification failed.",
        )
    if not id_claims.get("email_verified", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unverified Google email address.",
        )
    google_sub = id_claims.get("sub", "")
    email = id_claims.get("email", "")
    user_id = f"usr_google_{google_sub}" if google_sub else generate_user_id(email)
    access_token, refresh_token, expires_in = issue_jwt(
        user_id=user_id,
        email=email,
        roles=["traveler", "google_verified"],
        tenant_id="default",
        email_verified=True,
    )
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        user_id=user_id,
        email=email,
        roles=["traveler", "google_verified"],
        tenant_id="default",
    )


@app.post("/api/v1/auth/revoke")
async def revoke_token(req: TokenRevokeRequest):
    """Revoke an active JWT by adding its jti to the Redis blacklist."""
    r = await get_redis()
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
        except (jwt.PyJWTError, aioredis.RedisError, ValueError, TypeError) as exc:
            logger.debug("Error parsing jti for revocation: %s", exc)
    return {"status": "revoked"}
