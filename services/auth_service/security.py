"""
Cryptographic key management, RS256 signing, and JWKS generation.
"""

import base64
import os
import time
import uuid
from typing import Any

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KID = "travelbrain-key-2026-v1"
ISSUER = os.getenv("JWT_ISSUER", "https://auth.travelbrain.ai")
AUDIENCE = os.getenv("JWT_AUDIENCE", "https://api.travelbrain.ai")
ACCESS_TOKEN_EXPIRE_SECONDS = int(os.getenv("ACCESS_TOKEN_EXPIRE_SECONDS", "3600"))

_private_key: rsa.RSAPrivateKey | None = None


def int_to_base64url(val: int) -> str:
    """Convert integer to base64url encoded string without padding."""
    val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(val_bytes).rstrip(b"=").decode("ascii")


def get_private_key() -> rsa.RSAPrivateKey:
    """Load or generate the RSA private key."""
    global _private_key
    if _private_key is not None:
        return _private_key

    pem_path = os.getenv("JWT_PRIVATE_KEY_PATH")
    if pem_path and os.path.exists(pem_path):
        with open(pem_path, "rb") as f:
            _private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
    else:
        # Generate persistent in-memory 2048-bit key
        _private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
    return _private_key


def get_jwks() -> dict[str, Any]:
    """Export public key in JWKS RFC 7517 specification."""
    priv = get_private_key()
    pub = priv.public_key()
    numbers = pub.public_numbers()

    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": KID,
        "n": int_to_base64url(numbers.n),
        "e": int_to_base64url(numbers.e),
    }
    return {"keys": [jwk]}


def issue_jwt(
    user_id: str,
    email: str,
    roles: list[str] | None = None,
    tenant_id: str = "default",
    custom_claims: dict[str, Any] | None = None,
) -> tuple[str, int]:
    """Issue a signed RS256 JSON Web Token."""
    priv = get_private_key()
    now = int(time.time())
    exp = now + ACCESS_TOKEN_EXPIRE_SECONDS

    payload = {
        "iss": ISSUER,
        "sub": user_id,
        "aud": AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": exp,
        "jti": f"jwt_{uuid.uuid4().hex}",
        "email": email,
        "email_verified": True,
        "roles": roles or ["traveler"],
        "tenant_id": tenant_id,
    }
    if custom_claims:
        payload.update(custom_claims)

    token = jwt.encode(
        payload,
        priv,
        algorithm="RS256",
        headers={"kid": KID},
    )
    return token, ACCESS_TOKEN_EXPIRE_SECONDS
