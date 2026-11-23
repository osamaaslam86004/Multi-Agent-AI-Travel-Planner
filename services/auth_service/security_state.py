"""Distributed, fail-closed one-time state for OAuth, MFA, refresh, and step-up.
All security-critical records use Redis atomic operations with test fallback support.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any

from cryptography.fernet import Fernet
from fastapi import HTTPException

from services.core.config import get_settings
from services.shared.redis_client import get_redis_client


class SecurityStateUnavailable(RuntimeError):
    pass


_in_memory_sec_state: dict[str, Any] = {}


async def _redis():
    client = await get_redis_client()
    settings = get_settings()
    is_prod = settings.app.environment.lower() in ("production", "staging")
    if client is None:
        if is_prod:
            raise SecurityStateUnavailable("Distributed security state unavailable")
        return None
    try:
        await client.ping()
        return client
    except Exception:
        if is_prod:
            raise SecurityStateUnavailable("Distributed security state unavailable")
        return None


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _secret_cipher() -> Fernet:
    settings = get_settings()
    configured = settings.auth.identity_encryption_key
    if configured:
        try:
            return Fernet(configured.encode())
        except Exception as exc:
            raise RuntimeError(
                "IDENTITY_ENCRYPTION_KEY must be a valid Fernet key"
            ) from exc
    if settings.app.environment.lower() in ("production", "staging"):
        raise RuntimeError("IDENTITY_ENCRYPTION_KEY is required in production/staging")
    master = settings.auth.jwt_secret_key.encode("utf-8")
    key = __import__("base64").urlsafe_b64encode(
        hashlib.sha256(master + b"|identity-secrets").digest()
    )
    return Fernet(key)


def _encrypt_secret(secret: str) -> str:
    return _secret_cipher().encrypt(secret.encode()).decode()


def _decrypt_secret(ciphertext: str) -> str:
    return _secret_cipher().decrypt(ciphertext.encode()).decode()


async def put_once(key: str, value: dict[str, Any], ttl: int) -> None:
    r = await _redis()
    if r is not None:
        stored = await r.set(
            key, json.dumps(value, separators=(",", ":")), ex=ttl, nx=True
        )
        if not stored:
            raise HTTPException(status_code=409, detail="Security token collision")
        return
    if key in _in_memory_sec_state:
        raise HTTPException(status_code=409, detail="Security token collision")
    _in_memory_sec_state[key] = value


async def consume_once(key: str) -> dict[str, Any] | None:
    r = await _redis()
    if r is not None:
        raw = await r.getdel(key)
        if raw:
            try:
                val = json.loads(raw)
                return val if isinstance(val, dict) else None
            except (ValueError, TypeError):
                pass
    return _in_memory_sec_state.pop(key, None)


async def oauth_begin(
    provider: str,
    redirect_uri: str,
    tenant_id: str,
    org_id: str | None = None,
    purpose: str = "login",
    user_id: str | None = None,
) -> dict[str, str]:
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    nonce = secrets.token_urlsafe(32)
    challenge = (
        __import__("base64")
        .urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    await put_once(
        f"oauth_tx:{digest(state)}",
        {
            "provider": provider,
            "redirect_uri": redirect_uri,
            "verifier": verifier,
            "nonce": nonce,
            "tenant_id": tenant_id,
            "org_id": org_id,
            "purpose": purpose,
            "user_id": user_id,
            "created_at": int(time.time()),
        },
        600,
    )
    return {
        "state": state,
        "verifier": verifier,
        "nonce": nonce,
        "challenge": challenge,
    }


async def oauth_consume(state: str, provider: str) -> dict[str, Any]:
    tx = await consume_once(f"oauth_tx:{digest(state)}")
    if not tx or tx.get("provider") != provider:
        raise HTTPException(
            status_code=401, detail="Invalid or expired OAuth transaction"
        )
    if int(tx.get("created_at", 0)) + 600 < int(time.time()):
        raise HTTPException(status_code=401, detail="OAuth transaction expired")
    return tx


async def refresh_register(jti: str, user_id: str, sid: str, expires_at: int) -> None:
    ttl = max(1, expires_at - int(time.time()))
    await put_once(
        f"refresh:{digest(jti)}",
        {"user_id": user_id, "sid": sid, "expires_at": expires_at},
        ttl,
    )


async def refresh_consume(jti: str, user_id: str, sid: str) -> bool:
    entry = await consume_once(f"refresh:{digest(jti)}")
    return bool(entry and entry.get("user_id") == user_id and entry.get("sid") == sid)


async def sudo_register(
    jti: str, user_id: str, sid: str, action: str, ttl: int
) -> None:
    await put_once(
        f"sudo:{digest(jti)}", {"user_id": user_id, "sid": sid, "action": action}, ttl
    )


async def sudo_consume(jti: str, user_id: str, sid: str, action: str) -> bool:
    entry = await consume_once(f"sudo:{digest(jti)}")
    return bool(
        entry
        and entry.get("user_id") == user_id
        and entry.get("sid") == sid
        and entry.get("action") == action
    )


async def store_mfa_login_challenge(
    user_id: str,
    email: str,
    tenant_id: str = "default",
    org_id: str | None = None,
    roles: list[str] | None = None,
    ttl: int = 300,
) -> str:
    jti = secrets.token_urlsafe(32)
    state_payload = {
        "jti": jti,
        "user_id": user_id,
        "email": email,
        "tenant_id": tenant_id,
        "org_id": org_id,
        "roles": roles or ["member"],
        "created_at": int(time.time()),
    }
    await put_once(f"mfa_login_challenge:{digest(jti)}", state_payload, ttl)
    return jti


async def consume_mfa_login_challenge(jti: str) -> dict[str, Any] | None:
    return await consume_once(f"mfa_login_challenge:{digest(jti)}")


async def store_mfa_enrollment(user_id: str, secret: str, ttl: int = 600) -> None:
    r = await _redis()
    if r is not None:
        await r.set(
            f"mfa_enrollment:{digest(user_id)}", _encrypt_secret(secret), ex=ttl
        )
        return
    _in_memory_sec_state[f"mfa_enrollment:{digest(user_id)}"] = _encrypt_secret(secret)


async def consume_mfa_enrollment(user_id: str) -> str | None:
    r = await _redis()
    if r is not None:
        raw = await r.getdel(f"mfa_enrollment:{digest(user_id)}")
        return _decrypt_secret(raw) if raw else None
    raw = _in_memory_sec_state.pop(f"mfa_enrollment:{digest(user_id)}", None)
    return _decrypt_secret(raw) if raw else None


async def store_mfa_secret(user_id: str, secret: str, ttl: int = 600) -> None:
    await store_mfa_enrollment(user_id, secret, ttl)


async def save_mfa_secret(user_id: str, secret: str) -> None:
    r = await _redis()
    if r is not None:
        await r.set(f"mfa_secret:{digest(user_id)}", _encrypt_secret(secret))
        return
    _in_memory_sec_state[f"mfa_secret:{digest(user_id)}"] = _encrypt_secret(secret)


async def get_mfa_secret(user_id: str) -> str | None:
    r = await _redis()
    if r is not None:
        raw = await r.get(f"mfa_secret:{digest(user_id)}")
        return _decrypt_secret(raw) if raw else None
    raw = _in_memory_sec_state.get(f"mfa_secret:{digest(user_id)}")
    return _decrypt_secret(raw) if raw else None


async def delete_mfa_secret(user_id: str) -> None:
    r = await _redis()
    if r is not None:
        await r.delete(
            f"mfa_secret:{digest(user_id)}",
            f"mfa_backup:{digest(user_id)}",
            f"mfa_enrollment:{digest(user_id)}",
        )
        return
    _in_memory_sec_state.pop(f"mfa_secret:{digest(user_id)}", None)
    _in_memory_sec_state.pop(f"mfa_backup:{digest(user_id)}", None)
    _in_memory_sec_state.pop(f"mfa_enrollment:{digest(user_id)}", None)


async def save_backup_codes(user_id: str, codes: list[str]) -> None:
    r = await _redis()
    encoded = json.dumps([digest(c) for c in codes])
    if r is not None:
        await r.set(f"mfa_backup:{digest(user_id)}", encoded)
        return
    _in_memory_sec_state[f"mfa_backup:{digest(user_id)}"] = [digest(c) for c in codes]


async def consume_backup_code(user_id: str, code: str) -> bool:
    r = await _redis()
    code_digest = digest(code)
    if r is not None:
        key = f"mfa_backup:{digest(user_id)}"
        script = """
        local raw = redis.call('GET', KEYS[1])
        if not raw then return 0 end
        local codes = cjson.decode(raw)
        for i, c in ipairs(codes) do
          if c == ARGV[1] then table.remove(codes, i); redis.call('SET', KEYS[1], cjson.encode(codes)); return 1 end
        end
        return 0
        """
        return bool(await r.eval(script, 1, key, code_digest))
    codes = _in_memory_sec_state.get(f"mfa_backup:{digest(user_id)}")
    if codes and isinstance(codes, list) and code_digest in codes:
        codes.remove(code_digest)
        return True
    return False


async def revoke_session(sid: str, user_id: str, ttl: int = 86400) -> None:
    r = await _redis()
    if r is not None:
        await r.set(f"revoked_sid:{digest(sid)}", user_id, ex=ttl)
        return
    _in_memory_sec_state[f"revoked_sid:{digest(sid)}"] = user_id


async def is_session_revoked(sid: str) -> bool:
    r = await _redis()
    if r is not None:
        return bool(await r.get(f"revoked_sid:{digest(sid)}"))
    return f"revoked_sid:{digest(sid)}" in _in_memory_sec_state
