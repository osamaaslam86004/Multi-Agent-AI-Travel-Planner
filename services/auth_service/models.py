"""Pydantic models for Auth & Identity Service."""

from pydantic import BaseModel


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
    roles: list[str]
    tenant_id: str = "default"


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
