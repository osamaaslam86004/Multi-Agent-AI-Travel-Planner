"""
Stateless JWT verification middleware using JWKS public keys, non-blocking async fetching,
revocation checking, role/permission inheritance, and scoped FastAPI dependencies.
"""

import asyncio
import logging
from typing import Annotated, Any

import jwt
import redis.asyncio as aioredis
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWKClient, PyJWKClientError

from services.core.config import get_settings

logger = logging.getLogger("travelbrain.auth_middleware")
_s = get_settings()
AUTH_SERVICE_JWKS_URL = _s.auth.auth_service_jwks_url
EXPECTED_ISSUER = _s.auth.jwt_issuer
EXPECTED_AUDIENCE = _s.auth.jwt_audience
REDIS_URL = _s.redis.url

_jwks_client: PyJWKClient | None = None
_redis_client: Any = None
security_scheme = HTTPBearer(auto_error=False)
CredentialsDep = Annotated[
    HTTPAuthorizationCredentials | None, Depends(security_scheme)
]


def get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = PyJWKClient(
            AUTH_SERVICE_JWKS_URL, cache_keys=True, max_cached_keys=16
        )
    return _jwks_client


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
        except (aioredis.RedisError, OSError):
            _redis_client = None
    return _redis_client


class AuthenticatedUser:
    """Holds claims parsed from cryptographically verified JWT with RBAC capability."""

    def __init__(self, claims: dict[str, Any]):
        self.user_id: str = claims.get("sub", "")
        self.tenant_id: str = claims.get("tenant_id", "default")
        self.org_id: str | None = claims.get("org_id")
        self.email: str = claims.get("email", "")
        self.roles: list[str] = claims.get("roles", [])
        self.permissions: list[str] = claims.get("permissions", [])
        self.jti: str = claims.get("jti", "")
        self.session_id: str = claims.get("sid", "")
        self.mfa_verified: bool = claims.get("mfa_verified", True)
        self.raw_claims: dict[str, Any] = claims

    def has_role(self, role: str) -> bool:
        target = role.lower().strip()
        return any(
            r.lower().strip() == target for r in self.roles
        ) or "platform_owner" in [r.lower() for r in self.roles]

    def has_permission(self, permission: str) -> bool:
        if "*" in self.permissions or permission in self.permissions:
            return True
        prefix = permission.split(":")[0]
        return f"{prefix}:*" in self.permissions or "platform_owner" in [
            r.lower() for r in self.roles
        ]


async def get_current_user(
    request: Request, credentials: CredentialsDep = None
) -> AuthenticatedUser:
    token: str | None = None
    if credentials:
        token = credentials.credentials
    else:
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
        signing_key = await asyncio.to_thread(client.get_signing_key_from_jwt, token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=EXPECTED_AUDIENCE,
            issuer=EXPECTED_ISSUER,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
        jti = payload.get("jti")
        if jti:
            r = await get_redis()
            if r and await r.get(f"revoked:{jti}"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication token has been revoked.",
                    headers={"WWW-Authenticate": "Bearer error='invalid_token'"},
                )
        return AuthenticatedUser(payload)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token signature has expired.",
            headers={"WWW-Authenticate": "Bearer error='invalid_token'"},
        )
    except (jwt.InvalidTokenError, PyJWKClientError) as exc:
        logger.debug("JWT verification failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
            headers={"WWW-Authenticate": "Bearer error='invalid_token'"},
        )


CurrentUserDep = Annotated[AuthenticatedUser, Depends(get_current_user)]


def require_roles(*required_roles: str, require_all: bool = False):
    async def role_checker(user: CurrentUserDep) -> AuthenticatedUser:
        if require_all:
            for r in required_roles:
                if not user.has_role(r):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"User lacks required role: {r}",
                    )
        else:
            if required_roles and not any(user.has_role(r) for r in required_roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User lacks required access role.",
                )
        return user

    return role_checker


def require_any_role(*roles: str):
    return require_roles(*roles, require_all=False)


def require_all_roles(*roles: str):
    return require_roles(*roles, require_all=True)


def require_permission(required_permission: str):
    async def perm_checker(user: CurrentUserDep) -> AuthenticatedUser:
        if not user.has_permission(required_permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: missing '{required_permission}'",
            )
        return user

    return perm_checker


def require_reauth():
    async def reauth_checker(
        request: Request, user: CurrentUserDep
    ) -> AuthenticatedUser:
        sudo_hdr = request.headers.get("X-Sudo-Token")
        if not sudo_hdr:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Sensitive operation requires reauthentication (missing X-Sudo-Token).",
            )
        return user

    return reauth_checker
