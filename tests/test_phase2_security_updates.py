"""Focused unit tests for the distributed Phase 2 security-state helpers."""
import base64
import hashlib
import json

import pytest
from fastapi import HTTPException

from services.auth_service import security_state as state


class FakeRedis:
    def __init__(self):
        self.data = {}
    async def ping(self):
        return True
    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.data:
            return None
        self.data[key] = str(value)
        return True
    async def get(self, key):
        return self.data.get(key)
    async def getdel(self, key):
        return self.data.pop(key, None)
    async def eval(self, script, numkeys, key, code_hash):
        raw = self.data.get(key)
        if not raw:
            return 0
        codes = json.loads(raw)
        if code_hash in codes:
            codes.remove(code_hash)
            self.data[key] = json.dumps(codes)
            return 1
        return 0
@pytest.fixture
async def fake_redis(monkeypatch):
    client = FakeRedis()
    async def get_client():
        return client
    monkeypatch.setattr(state, "get_redis_client", get_client)
    return client
@pytest.mark.asyncio
async def test_oauth_state_is_single_use_and_pkce_s256_bound(fake_redis):
    tx = await state.oauth_begin(
        "google", "https://app.test/callback", "tenant-a", "org-a"
    )
    decoded_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(tx["verifier"].encode()).digest())
        .decode()
        .rstrip("=")
    )
    assert tx["challenge"] == decoded_challenge
    first = await state.oauth_consume(tx["state"], "google")
    assert first["verifier"] == tx["verifier"]
    with pytest.raises(HTTPException):
        await state.oauth_consume(tx["state"], "google")
@pytest.mark.asyncio
async def test_refresh_state_rotation_and_replay_detection(fake_redis):
    await state.refresh_register("jti-1", "user-1", "sid-1", 9999999999)
    assert await state.refresh_consume("jti-1", "user-1", "sid-1") is True
    assert await state.refresh_consume("jti-1", "user-1", "sid-1") is False
    assert await state.refresh_consume("jti-1", "other-user", "sid-1") is False
@pytest.mark.asyncio
async def test_sudo_token_context_and_single_use(fake_redis):
    await state.sudo_register("sudo-jti", "user-1", "sid-1", "/account/delete", 300)
    assert (
        await state.sudo_consume("sudo-jti", "user-1", "sid-1", "/account/delete")
        is True
    )
    assert (
        await state.sudo_consume("sudo-jti", "user-1", "sid-1", "/account/delete")
        is False
    )
    await state.sudo_register("sudo-jti-2", "user-1", "sid-1", "/account/delete", 300)
    assert (
        await state.sudo_consume("sudo-jti-2", "user-1", "sid-1", "/account/other")
        is False
    )
@pytest.mark.asyncio
async def test_mfa_secret_encryption_and_one_time_backup_codes(fake_redis):
    await state.store_mfa_secret("user-1", "TOTP-SECRET", ttl=600)
    raw = fake_redis.data[f"mfa_enrollment:{state.digest('user-1')}"]
    assert raw != "TOTP-SECRET"
    assert await state.consume_mfa_enrollment("user-1") == "TOTP-SECRET"
    assert await state.consume_mfa_enrollment("user-1") is None
    await state.save_backup_codes("user-1", ["backup-code"])
    assert await state.consume_backup_code("user-1", "backup-code") is True
    assert await state.consume_backup_code("user-1", "backup-code") is False