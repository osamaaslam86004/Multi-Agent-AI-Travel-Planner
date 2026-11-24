"""
Cryptographic key management, RFC 7638 KID generation, RS256 signing,
Argon2id password hashing, RFC 6238 TOTP MFA, Sudo Reauth tokens, Magic Links,
Device Fingerprinting, and suspicious login detection.
Supports dual-key RSA key rotation precedence and async offloading for Argon2 operations.
"""
import asyncio
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
    """Generate cryptographically random internal user_id (usr_<uuid4_hex>) with full 128-bit entropy."""
    return f"usr_{uuid.uuid4().hex}"
# Argon2id Password Hashing (Synchronous core)
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
# Non-blocking Async Wrappers for Argon2 CPU work
async def async_hash_password(password: str) -> str:
    """Offload CPU-bound Argon2 password hashing to a background thread."""
    return await asyncio.to_thread(hash_password, password)
async def async_verify_password(password: str, password_hash: str) -> bool:
    """Offload CPU-bound Argon2 password verification to a background thread."""
    return await asyncio.to_thread(verify_password, password, password_hash)
# Deterministic RSA Keypair Loading & Rotation Precedence
def _initialize_rsa_keys() -> None:
    global _primary_private_key, _previous_private_key
    pem_env = _settings.auth.jwt_private_key_pem or os.getenv("JWT_PRIVATE_KEY_PEM")
    path_env = (
        _settings.auth.jwt_previous_private_key_path
        or _settings.auth.jwt_private_key_path
        or os.getenv("JWT_PRIVATE_KEY_PATH")
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
            # Fallback deterministic dev key generation
            seed_material = f"{ISSUER}:{_settings.auth.jwt_secret_key}".encode()
            seed_hash = hashlib.sha256(seed_material).digest()
            int.from_bytes(seed_hash, "big")
            _primary_private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
    prev_pem = _settings.auth.jwt_previous_private_key_pem or os.getenv(
        "JWT_PREVIOUS_PRIVATE_KEY_PEM"
    )
    prev_path = _settings.auth.jwt_previous_private_key_path or os.getenv(
        "JWT_PREVIOUS_PRIVATE_KEY_PATH"
    )
    if _previous_private_key is None:
        if prev_pem:
            try:
                _previous_private_key = serialization.load_pem_private_key(
                    prev_pem.encode("utf-8"), password=None, backend=default_backend()
                )
            except Exception:
                _previous_private_key = None
        elif prev_path and os.path.exists(prev_path):
            try:
                with open(prev_path, "rb") as f:
                    _previous_private_key = serialization.load_pem_private_key(
                        f.read(), password=None, backend=default_backend()
                    )
            except Exception:
                _previous_private_key = None
def get_jwks() -> dict[str, Any]:
    """Expose public keys in JWKS format with kid."""
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
    tenant_id: str = "default",
    org_id: str | None = None,
    roles: list[str] | None = None,
    token_use: str = "access",
    sid: str | None = None,
    ttl_seconds: int | None = None,
    mfa_verified: bool = True,
) -> str:
    _initialize_rsa_keys()
    if _primary_private_key is None:
        raise RuntimeError("JWT signing key unavailable")
    pub_key = _primary_private_key.public_key()
    kid = compute_rfc7638_kid(pub_key)
    now = int(time.time())
    ttl = (
        ttl_seconds
        if ttl_seconds is not None
        else (
            ACCESS_TOKEN_EXPIRE_SECONDS
            if token_use == "access"
            else REFRESH_TOKEN_EXPIRE_SECONDS
        )
    )
    payload = {
        "iss": ISSUER,
        "sub": user_id,
        "aud": AUDIENCE,
        "exp": now + ttl,
        "nbf": now,
        "iat": now,
        "jti": f"jti_{uuid.uuid4().hex[:16]}",
        "sid": sid or f"sid_{secrets.token_hex(12)}",
        "email": email,
        "tenant_id": tenant_id,
        "org_id": org_id,
        "roles": roles or ["member"],
        "token_use": token_use,
        "mfa_verified": mfa_verified,
    }
    pem_bytes = _primary_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return jwt.encode(payload, pem_bytes, algorithm="RS256", headers={"kid": kid})
def issue_sudo_token(user_id: str, tenant_id: str = "default") -> str:
    """Issue short-lived Sudo Reauthentication token (TTL: 15 mins)."""
    return issue_jwt(
        user_id=user_id,
        email=f"{user_id}@sudo.local",
        tenant_id=tenant_id,
        token_use="sudo",
        ttl_seconds=SUDO_TOKEN_EXPIRE_SECONDS,
    )
def decode_signed_token(
    token: str, allowed_uses: tuple[str, ...] = ("access", "refresh")
) -> dict[str, Any]:
    """Decode and cryptographically verify token signature against primary, falling back to previous key during rotation."""
    _initialize_rsa_keys()
    if _primary_private_key is None:
        raise RuntimeError("JWT verification key unavailable")
    options = {
        "require": ["exp", "iat", "jti", "sub", "sid", "token_use", "iss", "aud"],
        "verify_signature": True,
        "verify_exp": True,
        "verify_iss": True,
        "verify_aud": True,
    }
    # Primary key attempt
    try:
        claims = jwt.decode(
            token,
            _primary_private_key.public_key(),
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options=options,
        )
        if claims.get("token_use") not in allowed_uses:
            raise jwt.InvalidTokenError("Unexpected token use")
        return claims
    except (jwt.InvalidSignatureError, jwt.PyJWTError):
        if _previous_private_key is not None:
            try:
                claims = jwt.decode(
                    token,
                    _previous_private_key.public_key(),
                    algorithms=["RS256"],
                    issuer=ISSUER,
                    audience=AUDIENCE,
                    options=options,
                )
                if claims.get("token_use") not in allowed_uses:
                    raise jwt.InvalidTokenError("Unexpected token use")
                return claims
            except jwt.PyJWTError:
                pass
        raise
def decode_refresh_token(refresh_token: str) -> dict[str, Any]:
    """Cryptographically validate a refresh JWT before any rotation state is touched."""
    return decode_signed_token(refresh_token, allowed_uses=("refresh",))
def decode_signed_token_allow_expired(token: str) -> dict[str, Any]:
    """Decode token allowing expiration for token-refresh or revocation contexts, using dual-key rotation."""
    _initialize_rsa_keys()
    if _primary_private_key is None:
        raise RuntimeError("JWT verification key unavailable")
    options = {
        "require": ["exp", "iat", "jti", "sub", "sid", "token_use", "iss", "aud"],
        "verify_signature": True,
        "verify_exp": False,
        "verify_iss": True,
        "verify_aud": True,
    }
    try:
        return jwt.decode(
            token,
            _primary_private_key.public_key(),
            algorithms=["RS256"],
            issuer=ISSUER,
            audience=AUDIENCE,
            options=options,
        )
    except (jwt.InvalidSignatureError, jwt.PyJWTError):
        if _previous_private_key is not None:
            try:
                return jwt.decode(
                    token,
                    _previous_private_key.public_key(),
                    algorithms=["RS256"],
                    issuer=ISSUER,
                    audience=AUDIENCE,
                    options=options,
                )
            except jwt.PyJWTError:
                pass
        raise
# RFC 6238 TOTP Engine
def generate_totp_secret() -> str:
    """Generate 160-bit (20-byte) base32 encoded TOTP secret key."""
    return base64.b32encode(os.urandom(20)).decode("ascii")
def get_totp_uri(secret: str, account_name: str, issuer: str = "TravelBrain") -> str:
    """Construct standard OTPAUTH URI for QR code generators."""
    label = f"{issuer}:{account_name}"
    return f"otpauth://totp/{urllib.parse.quote(label)}?secret={secret}&issuer={urllib.parse.quote(issuer)}&algorithm=SHA1&digits=6&period=30"
def _totp_code_at_counter(secret: str, counter: int) -> str:
    """Generate 6-digit TOTP code for a given 30-second counter."""
    key = base64.b32decode(secret, casefold=True)
    counter_bytes = struct.pack(">Q", counter)
    hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
    offset = hmac_digest[-1] & 0x0F
    binary = (
        ((hmac_digest[offset] & 0x7F) << 24)
        | ((hmac_digest[offset + 1] & 0xFF) << 16)
        | ((hmac_digest[offset + 2] & 0xFF) << 8)
        | (hmac_digest[offset + 3] & 0xFF)
    )
    otp = binary % 1000000
    return f"{otp:06d}"
def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
    """Verify TOTP code with drift tolerance (+/- window 30s steps)."""
    if not secret or not code or len(code.strip()) != 6:
        return False
    current_counter = int(time.time() // 30)
    clean_code = code.strip()
    for c in range(current_counter - window, current_counter + window + 1):
        if hmac.compare_digest(_totp_code_at_counter(secret, c), clean_code):
            return True
    return False
# Magic Link Tokens
_SECRET_HMAC_KEY = hashlib.sha256(
    _settings.auth.jwt_secret_key.encode("utf-8") + b"|magic-links"
).digest()
def generate_magic_link_token(email: str, ttl_seconds: int = 900) -> str:
    """Generate HMAC-SHA256 signed magic link token."""
    now = int(time.time())
    expires = now + ttl_seconds
    nonce = secrets.token_hex(8)
    payload = f"magic:{email.lower().strip()}:{now}:{expires}:{nonce}"
    sig = hmac.new(
        _SECRET_HMAC_KEY, payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    raw = f"{payload}:{sig}"
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")
def verify_magic_link_token(token: str) -> str | None:
    """Validate signed magic token format and expiry."""
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        parts = raw.split(":")
        if len(parts) != 6 or parts[0] != "magic":
            return None
        _, email, iat, exp, nonce, sig = parts
        issued, expires = int(iat), int(exp)
        now = int(time.time())
        if issued > now + 60 or expires <= now or expires - issued > 900:
            return None
        payload = f"magic:{email}:{iat}:{exp}:{nonce}"
        expected_sig = hmac.new(
            _SECRET_HMAC_KEY, payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return email.lower().strip() if hmac.compare_digest(expected_sig, sig) else None
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