"""
Cryptographic key management, RFC 7638 KID generation, RS256 signing,
Argon2id password hashing, RFC 6238 TOTP MFA, Sudo Reauth tokens, Magic Links,
Device Fingerprinting, and suspicious login detection.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
import uuid
from typing import Any

import jwt
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from services.core.config import get_settings

_settings = get_settings()
ISSUER = _settings.auth.jwt_issuer
AUDIENCE = _settings.auth.jwt_audience
ACCESS_TOKEN_EXPIRE_SECONDS = _settings.auth.access_token_expire_seconds
REFRESH_TOKEN_EXPIRE_SECONDS = _settings.auth.refresh_token_expire_seconds
SUDO_TOKEN_EXPIRE_SECONDS = _settings.auth.sudo_token_expire_seconds
_primary_private_key: rsa.RSAPrivateKey | None = None
_previous_private_key: rsa.RSAPrivateKey | None = None


def int_to_base64url(val: int) -> str:
    """Convert integer to base64url encoded string without padding."""
    val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(val_bytes).rstrip(b"=").decode("ascii")


def compute_rfc7638_kid(pub_key: rsa.RSAPublicKey) -> str:
    """Compute RFC 7638 JSON Web Key (JWK) Thumbprint as Key ID (kid)."""
    numbers = pub_key.public_numbers()
    canonical_dict = {
        "e": int_to_base64url(numbers.e),
        "kty": "RSA",
        "n": int_to_base64url(numbers.n),
    }
    canonical_json = json.dumps(canonical_dict, separators=(",", ":"))
    digest = hashlib.sha256(canonical_json.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def generate_user_id(email: str | None = None) -> str:
    """Action Item 6 & Step 6: Generate cryptographically random internal user_id (usr_<uuid4_hex>) with full 128-bit entropy."""
    return f"usr_{uuid.uuid4().hex}"


# Argon2id Password Hashing
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
    except (ValueError, TypeError, InvalidKey):
        return False


# Step 3 (C-6): Deterministic RSA Keypair Loading
def _initialize_rsa_keys() -> None:
    global _primary_private_key, _previous_private_key
    pem_env = _settings.auth.jwt_previous_private_key_pem or os.getenv(
        "JWT_PRIVATE_KEY_PEM"
    )
    path_env = _settings.auth.jwt_previous_private_key_path or os.getenv(
        "JWT_PRIVATE_KEY_PATH"
    )
    if _primary_private_key is None:
        if pem_env:
            try:
                _primary_private_key = serialization.load_pem_private_key(
                    pem_env.encode("utf-8"), password=None, backend=default_backend()
                )
            except Exception:
                _primary_private_key = None
        elif path_env and os.path.exists(path_env):
            try:
                with open(path_env, "rb") as f:
                    _primary_private_key = serialization.load_pem_private_key(
                        f.read(), password=None, backend=default_backend()
                    )
            except Exception:
                _primary_private_key = None
        if _primary_private_key is None:
            if _settings.app.environment.lower() in ("production", "staging"):
                raise RuntimeError(
                    "RSA Primary Signing Key (JWT_PRIVATE_KEY_PEM) is required in staging/production."
                )
            _primary_private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
    prev_pem = os.getenv("JWT_PREVIOUS_PRIVATE_KEY_PEM")
    if prev_pem and _previous_private_key is None:
        try:
            _previous_private_key = serialization.load_pem_private_key(
                prev_pem.encode("utf-8"), password=None, backend=default_backend()
            )
        except Exception:
            _previous_private_key = None


def get_jwks() -> dict[str, Any]:
    _initialize_rsa_keys()
    keys = []
    if _primary_private_key:
        pub = _primary_private_key.public_key()
        numbers = pub.public_numbers()
        keys.append(
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": compute_rfc7638_kid(pub),
                "n": int_to_base64url(numbers.n),
                "e": int_to_base64url(numbers.e),
            }
        )
    if _previous_private_key:
        pub_prev = _previous_private_key.public_key()
        numbers_prev = pub_prev.public_numbers()
        keys.append(
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": compute_rfc7638_kid(pub_prev),
                "n": int_to_base64url(numbers_prev.n),
                "e": int_to_base64url(numbers_prev.e),
            }
        )
    return {"keys": keys}


def issue_jwt(
    user_id: str,
    email: str,
    roles: list[str] | None = None,
    permissions: list[str] | None = None,
    tenant_id: str = "default",
    org_id: str | None = None,
    email_verified: bool = False,
    mfa_verified: bool = True,
    session_id: str | None = None,
) -> tuple[str, str, int]:
    _initialize_rsa_keys()
    if _primary_private_key is None:
        raise RuntimeError("RSA Key not initialized")
    now = int(time.time())
    access_exp = now + ACCESS_TOKEN_EXPIRE_SECONDS
    pub_key = _primary_private_key.public_key()
    kid = compute_rfc7638_kid(pub_key)
    jti = f"jti_{uuid.uuid4().hex}"
    sid = session_id or f"sid_{uuid.uuid4().hex}"
    claims = {
        "iss": ISSUER,
        "sub": user_id,
        "aud": AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": access_exp,
        "jti": jti,
        "sid": sid,
        "tenant_id": tenant_id,
        "org_id": org_id,
        "email": email,
        "email_verified": email_verified,
        "mfa_verified": mfa_verified,
        "token_use": "access",  # Step 5 (H-1)
        "roles": roles or ["member"],
        "permissions": permissions or [],
    }
    private_pem = _primary_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    access_token = jwt.encode(
        claims, private_pem, algorithm="RS256", headers={"kid": kid}
    )
    refresh_exp = now + REFRESH_TOKEN_EXPIRE_SECONDS
    refresh_claims = {
        "iss": ISSUER,
        "sub": user_id,
        "aud": AUDIENCE,
        "iat": now,
        "exp": refresh_exp,
        "jti": f"refresh_{uuid.uuid4().hex}",
        "sid": sid,
        "token_use": "refresh",  # Step 5 (H-1)
    }
    refresh_token = jwt.encode(
        refresh_claims, private_pem, algorithm="RS256", headers={"kid": kid}
    )
    return access_token, refresh_token, ACCESS_TOKEN_EXPIRE_SECONDS


def generate_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _generate_totp_code(secret: str, time_step: int | None = None) -> str:
    if time_step is None:
        time_step = int(time.time()) // 30
    padding = "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode((secret + padding).encode("ascii"), casefold=True)
    msg = struct.pack(">Q", time_step)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[19] & 0x0F
    code_int = (
        (digest[offset] & 0x7F) << 24
        | (digest[offset + 1] & 0xFF) << 16
        | (digest[offset + 2] & 0xFF) << 8
        | (digest[offset + 3] & 0xFF)
    ) % 1000000
    return f"{code_int:06d}"


def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
    if not secret or not code:
        return False
    current_step = int(time.time()) // 30
    for step_offset in range(-window, window + 1):
        candidate = _generate_totp_code(secret, current_step + step_offset)
        if hmac.compare_digest(candidate, code.strip()):
            return True
    return False


def get_totp_uri(secret: str, email: str, issuer: str = "TravelBrain") -> str:
    import urllib.parse

    label = urllib.parse.quote(f"{issuer}:{email}")
    issuer_q = urllib.parse.quote(issuer)
    return f"otpauth://totp/{label}?secret={secret}&issuer={issuer_q}&algorithm=SHA1&digits=6&period=30"


_SECRET_HMAC_KEY = _settings.auth.jwt_secret_key.encode("utf-8")


def issue_sudo_token(user_id: str) -> str:
    now = int(time.time())
    payload = (
        f"{user_id}:{now}:{now + SUDO_TOKEN_EXPIRE_SECONDS}:{secrets.token_hex(8)}"
    )
    sig = hmac.new(
        _SECRET_HMAC_KEY, payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    raw = f"{payload}:{sig}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def verify_sudo_token(sudo_token: str, expected_user_id: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(sudo_token.encode("ascii")).decode("utf-8")
        parts = raw.split(":")
        if len(parts) != 5:
            return False
        uid, iat, exp, nonce, sig = parts
        if uid != expected_user_id or int(exp) < time.time():
            return False
        payload = f"{uid}:{iat}:{exp}:{nonce}"
        expected_sig = hmac.new(
            _SECRET_HMAC_KEY, payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected_sig, sig)
    except Exception:
        return False


def issue_magic_link_token(email: str) -> str:
    now = int(time.time())
    email_clean = email.lower().strip()
    payload = f"magic:{email_clean}:{now}:{now + 900}:{secrets.token_hex(8)}"
    sig = hmac.new(
        _SECRET_HMAC_KEY, payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    raw = f"{payload}:{sig}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def verify_magic_link_token(token: str) -> str | None:
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        parts = raw.split(":")
        if len(parts) != 5 or parts[0] != "magic":
            return None
        _, email, iat, exp, nonce, sig = parts
        if int(exp) < time.time():
            return None
        payload = f"magic:{email}:{iat}:{exp}:{nonce}"
        expected_sig = hmac.new(
            _SECRET_HMAC_KEY, payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return email if hmac.compare_digest(expected_sig, sig) else None
    except Exception:
        return None


def compute_device_fingerprint(user_agent: str, ip_address: str) -> str:
    subnet = ".".join(ip_address.split(".")[:3]) if "." in ip_address else ip_address
    compiled = f"{user_agent.strip().lower()}:{subnet}"
    return f"fp_{hashlib.sha256(compiled.encode('utf-8')).hexdigest()[:16]}"


def assess_suspicious_login(
    user_id: str,
    ip_address: str,
    user_agent: str,
    recent_history: list[dict[str, Any]],
) -> tuple[bool, str | None]:
    if not recent_history:
        return False, None
    current_fp = compute_device_fingerprint(user_agent, ip_address)
    known_fps = {
        compute_device_fingerprint(h.get("user_agent", ""), h.get("ip_address", ""))
        for h in recent_history
        if h.get("status") == "success"
    }
    if known_fps and current_fp not in known_fps:
        return True, "Login from an unrecognized device/IP fingerprint."
    return False, None
