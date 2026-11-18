"""Pydantic models for Auth & Identity Service."""

from pydantic import BaseModel, EmailStr


class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str | None = None
    tenant_id: str = "default"


class GoogleTokenExchangeRequest(BaseModel):
    code: str
    redirect_uri: str
    code_verifier: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    user_id: str
    email: str
    roles: list[str]


class JWKKey(BaseModel):
    kty: str = "RSA"
    use: str = "sig"
    alg: str = "RS256"
    kid: str
    n: str
    e: str


class JWKSResponse(BaseModel):
    keys: list[JWKKey]
