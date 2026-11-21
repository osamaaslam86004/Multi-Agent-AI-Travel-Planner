"""
Cryptographic key management, RFC 7638 KID generation, RS256 signing,
Argon2id password hashing, and multi-key JWKS rotation overlap.
"""

import base64
import hashlib
import json
import os
import time
import uuid
from typing import Any

import jwt
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

ISSUER = os.getenv("JWT_ISSUER", "https://" + "auth.travelbrain.ai")
AUDIENCE = os.getenv("JWT_AUDIENCE", "https://" + "api.travelbrain.ai")
ACCESS_TOKEN_EXPIRE_SECONDS = int(os.getenv("ACCESS_TOKEN_EXPIRE_SECONDS", "3600"))
REFRESH_TOKEN_EXPIRE_SECONDS = int(os.getenv("REFRESH_TOKEN_EXPIRE_SECONDS", "604800"))
_primary_private_key: rsa.RSAPrivateKey | None = None
_previous_private_key: rsa.RSAPrivateKey | None = None


def int_to_base64url(val: int) -> str:
    """Convert integer to base64url encoded string without padding."""
    val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(val_bytes).rstrip(b"=").decode("ascii")


def compute_rfc7638_kid(pub_key: rsa.RSAPublicKey) -> str:
    """Compute RFC 7638 JSON Web Key (JWK) Thumbprint as the Key ID (kid)."""
    numbers = pub_key.public_numbers()
    canonical_dict = {
        "e": int_to_base64url(numbers.e),
        "kty": "RSA",
        "n": int_to_base64url(numbers.n),
    }
    canonical_json = json.dumps(canonical_dict, separators=(",", ":"))
    digest = hashlib.sha256(canonical_json.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def generate_user_id(email: str) -> str:
    """Generate stable, deterministic user_id from email using UUIDv5."""
    target = f"mailto:{email.lower().strip()}"
    return f"usr_{uuid.uuid5(uuid.NAMESPACE_URL, target).hex}"


def hash_password(password: str) -> str:
    """Hash password using Argon2id."""
    salt = os.urandom(16)
    kdf = Argon2id(salt=salt, length=32, iterations=3, memory_cost=65536, lanes=4)
    key = kdf.derive(password.encode("utf-8"))
    salt_b64 = base64.b64encode(salt).decode("ascii")
    key_b64 = base64.b64encode(key).decode("ascii")
    return f"argon2id$v=19$m=65536,t=3,p=4${salt_b64}${key_b64}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against Argon2id hash."""
    try:
        parts = password_hash.split("$")
        if len(parts) != 5 or parts[0] != "argon2id":
            return False
        salt = base64.b64decode(parts[3])
        expected_key = base64.b64decode(parts[4])
        kdf = Argon2id(
            salt=salt,
            length=len(expected_key),
            iterations=3,
            memory_cost=65536,
            lanes=4,
        )
        kdf.verify(password.encode("utf-8"), expected_key)
        return True
    except (InvalidKey, ValueError, TypeError):
        return False


def _load_key_from_pem_or_env(
    pem_path_env: str, pem_str_env: str, fallback_path: str
) -> rsa.RSAPrivateKey:
    """Helper to load RSA private key from env string, file path, or persistent fallback."""
    pem_bytes: bytes | None = None
    pem_str = os.getenv(pem_str_env)
    if pem_str:
        pem_bytes = pem_str.strip().encode("utf-8")
    else:
        pem_path = os.getenv(pem_path_env)
        if pem_path and os.path.exists(pem_path):
            with open(pem_path, "rb") as f:
                pem_bytes = f.read()
    if pem_bytes:
        return serialization.load_pem_private_key(
            pem_bytes, password=None, backend=default_backend()
        )
    if os.path.exists(fallback_path):
        with open(fallback_path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    try:
        os.makedirs(os.path.dirname(fallback_path), exist_ok=True)
        with open(fallback_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    except OSError:
        pass
    return key


def get_primary_private_key() -> rsa.RSAPrivateKey:
    """Load or initialize primary RSA private key."""
    global _primary_private_key
    if _primary_private_key is not None:
        return _primary_private_key
    fallback_path = os.getenv(
        "JWT_PRIMARY_FALLBACK_PATH", "/tmp/tb_jwt_primary_private.pem"
    )
    _primary_private_key = _load_key_from_pem_or_env(
        "JWT_PRIVATE_KEY_PATH", "JWT_PRIVATE_KEY_PEM", fallback_path
    )
    return _primary_private_key


def get_previous_private_key() -> rsa.RSAPrivateKey | None:
    """Load optional previous RSA private key to support rotation overlap."""
    global _previous_private_key
    if _previous_private_key is not None:
        return _previous_private_key
    pem_path = os.getenv("JWT_PREVIOUS_PRIVATE_KEY_PATH")
    pem_str = os.getenv("JWT_PREVIOUS_PRIVATE_KEY_PEM")
    if pem_str:
        pem_bytes = pem_str.strip().encode("utf-8")
        _previous_private_key = serialization.load_pem_private_key(
            pem_bytes, password=None, backend=default_backend()
        )
    elif pem_path and os.path.exists(pem_path):
        with open(pem_path, "rb") as f:
            _previous_private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
    return _previous_private_key


def get_jwks() -> dict[str, Any]:
    """Export public keys in JWKS RFC 7517 specification for all active keys (rotation overlap)."""
    keys = []
    primary_priv = get_primary_private_key()
    primary_pub = primary_priv.public_key()
    primary_kid = compute_rfc7638_kid(primary_pub)
    primary_num = primary_pub.public_numbers()
    keys.append(
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": primary_kid,
            "n": int_to_base64url(primary_num.n),
            "e": int_to_base64url(primary_num.e),
        }
    )
    prev_priv = get_previous_private_key()
    if prev_priv:
        prev_pub = prev_priv.public_key()
        prev_kid = compute_rfc7638_kid(prev_pub)
        prev_num = prev_pub.public_numbers()
        if prev_kid != primary_kid:
            keys.append(
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": prev_kid,
                    "n": int_to_base64url(prev_num.n),
                    "e": int_to_base64url(prev_num.e),
                }
            )
    return {"keys": keys}


def issue_jwt(
    user_id: str,
    email: str,
    roles: list[str] | None = None,
    tenant_id: str = "default",
    custom_claims: dict[str, Any] | None = None,
    email_verified: bool = True,
) -> tuple[str, str, int]:
    """Issue signed RS256 access and refresh tokens with RFC 7638 KID."""
    priv = get_primary_private_key()
    pub = priv.public_key()
    kid = compute_rfc7638_kid(pub)
    now = int(time.time())
    exp = now + ACCESS_TOKEN_EXPIRE_SECONDS
    jti = f"jwt_{uuid.uuid4().hex}"
    payload = {
        "iss": ISSUER,
        "sub": user_id,
        "aud": AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": exp,
        "jti": jti,
        "email": email,
        "email_verified": email_verified,
        "roles": roles or ["traveler"],
        "tenant_id": tenant_id,
    }
    if custom_claims:
        payload.update(custom_claims)
    access_token = jwt.encode(
        payload,
        priv,
        algorithm="RS256",
        headers={"kid": kid},
    )
    refresh_jti = f"ref_{uuid.uuid4().hex}"
    refresh_payload = {
        "iss": ISSUER,
        "sub": user_id,
        "aud": AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": now + REFRESH_TOKEN_EXPIRE_SECONDS,
        "jti": refresh_jti,
        "type": "refresh",
        "email": email,
        "tenant_id": tenant_id,
    }
    refresh_token = jwt.encode(
        refresh_payload,
        priv,
        algorithm="RS256",
        headers={"kid": kid},
    )
    return access_token, refresh_token, ACCESS_TOKEN_EXPIRE_SECONDS
