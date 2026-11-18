"""
Auth & Identity Microservice (Google OIDC + RS256 JWT Issuance + JWKS).
"""

import os
import secrets
import urllib.parse

import httpx
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from services.auth_service.models import (
    GoogleTokenExchangeRequest,
    JWKSResponse,
    TokenResponse,
    UserLoginRequest,
)
from services.auth_service.security import get_jwks, issue_jwt

app = FastAPI(
    title="TravelBrain Auth & Identity Service",
    version="2.0.0",
    description="Enterprise OIDC Authentication, RS256 JWT Issuance & JWKS Provider",
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
    "https://accounts.google.com/.well-known/openid-configuration"
)


@app.get("/.well-known/jwks.json", response_model=JWKSResponse)
def jwks_endpoint():
    """Public JWKS endpoint for downstream microservices to verify JWT signatures."""
    return get_jwks()


@app.get("/health/live")
def liveness():
    return {"status": "UP", "service": "auth-service"}


@app.get("/health/ready")
def readiness():
    # Verify private key availability
    try:
        jwks = get_jwks()
        if not jwks["keys"]:
            raise RuntimeError("JWKS keys empty")
        return {"status": "READY", "keys_loaded": len(jwks["keys"])}
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        )


@app.post("/api/v1/auth/login", response_model=TokenResponse)
def direct_login(req: UserLoginRequest):
    """
    Direct login / testing authentication endpoint.
    Issues RS256 signed JWT with user claims.
    """
    user_id = f"usr_{abs(hash(req.email)) % 10000000}"
    roles = ["traveler"]
    if "admin" in req.email:
        roles.append("admin")

    token, expires_in = issue_jwt(
        user_id=user_id,
        email=req.email,
        roles=roles,
        tenant_id=req.tenant_id,
    )
    return TokenResponse(
        access_token=token,
        expires_in=expires_in,
        user_id=user_id,
        email=req.email,
        roles=roles,
    )


@app.get("/api/v1/auth/google/url")
def get_google_auth_url(redirect_uri: str):
    """Generate Google OIDC authorization URL with CSRF state."""
    state = secrets.token_urlsafe(32)
    params = {
        "client_id": GOOGLE_CLIENT_ID or "mock-google-client-id",
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "state": state,
        "prompt": "consent",
    }
    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?{urllib.parse.urlencode(params)}"
    )
    return {"auth_url": auth_url, "state": state}


@app.post("/api/v1/auth/google/callback", response_model=TokenResponse)
async def google_callback(req: GoogleTokenExchangeRequest):
    """
    Exchange Google authorization code for identity tokens, verify user,
    and issue an internal TravelBrain RS256 JWT.
    """
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        # Development / Sandbox mock fallback when credentials not provided
        mock_user_id = "usr_google_sandbox_99"
        mock_email = "traveler.google@sandbox.travelbrain.ai"
        token, expires_in = issue_jwt(
            user_id=mock_user_id,
            email=mock_email,
            roles=["traveler", "google_verified"],
        )
        return TokenResponse(
            access_token=token,
            expires_in=expires_in,
            user_id=mock_user_id,
            email=mock_email,
            roles=["traveler", "google_verified"],
        )

    # Real Google Token Exchange
    token_url = "https://oauth2.googleapis.com/token"
    data = {
        "code": req.code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": req.redirect_uri,
        "grant_type": "authorization_code",
    }
    if req.code_verifier:
        data["code_verifier"] = req.code_verifier

    async with httpx.AsyncClient() as client:
        resp = await client.post(token_url, data=data)
        if resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Google OAuth exchange failed: {resp.text}",
            )
        tokens = resp.json()
        id_token_raw = tokens.get("id_token")

        userinfo_resp = await client.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {tokens.get('access_token')}"},
        )
        if userinfo_resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed fetching Google user profile",
            )
        profile = userinfo_resp.json()

    user_id = f"usr_google_{profile.get('sub')}"
    email = profile.get("email", "unknown@gmail.com")
    token, expires_in = issue_jwt(
        user_id=user_id,
        email=email,
        roles=["traveler", "google_verified"],
        custom_claims={"name": profile.get("name", "")},
    )
    return TokenResponse(
        access_token=token,
        expires_in=expires_in,
        user_id=user_id,
        email=email,
        roles=["traveler", "google_verified"],
    )
