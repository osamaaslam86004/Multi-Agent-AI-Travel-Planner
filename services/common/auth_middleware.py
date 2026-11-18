"""
Stateless JWT verification middleware using JWKS public keys.
"""

import os
from typing import Any

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient, PyJWKClientError

AUTH_SERVICE_JWKS_URL = os.getenv(
    "AUTH_SERVICE_JWKS_URL", "http://auth-service:8001/.well-known/jwks.json"
)
EXPECTED_ISSUER = os.getenv("JWT_ISSUER", "https://auth.travelbrain.ai")
EXPECTED_AUDIENCE = os.getenv("JWT_AUDIENCE", "https://api.travelbrain.ai")

_jwks_client: PyJWKClient | None = None
security_scheme = HTTPBearer(auto_error=False)


def get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(
            AUTH_SERVICE_JWKS_URL, cache_keys=True, max_cached_keys=16
        )
    return _jwks_client


class AuthenticatedUser:
    """Holds claims parsed from cryptographically verified JWT."""

    def __init__(self, claims: dict[str, Any]):
        self.user_id: str = claims.get("sub", "")
        self.tenant_id: str = claims.get("tenant_id", "default")
        self.email: str = claims.get("email", "")
        self.roles: list[str] = claims.get("roles", [])
        self.permissions: list[str] = claims.get("permissions", [])
        self.raw_claims: dict[str, Any] = claims

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
) -> AuthenticatedUser:
    """
    Statelessly verifies incoming JWT signature via local JWKS cache.
    Zero database hits; zero auth-server round-trips after keys are cached.
    """
    token: str | None = None
    if credentials:
        token = credentials.credentials
    else:
        # Fallback to header or X-Internal-Token
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        client = get_jwks_client()
        signing_key = client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=EXPECTED_AUDIENCE,
            issuer=EXPECTED_ISSUER,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
        return AuthenticatedUser(payload)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token signature has expired.",
            headers={"WWW-Authenticate": "Bearer error='invalid_token'"},
        )
    except (jwt.InvalidTokenError, PyJWKClientError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Cryptographic signature verification failed: {exc}",
            headers={"WWW-Authenticate": "Bearer error='invalid_token'"},
        )


def require_roles(*required_roles: str):
    """Role-Based Access Control (RBAC) dependency factory."""

    async def role_checker(
        user: AuthenticatedUser = Depends(get_current_user),
    ) -> AuthenticatedUser:
        for r in required_roles:
            if not user.has_role(r):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"User lacks required role: {r}",
                )
        return user

    return role_checker
