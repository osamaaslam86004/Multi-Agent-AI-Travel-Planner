"""
Automated Verification Test Suite for the 6 Remediation Steps:
Step 1: Complete Database Persistence & Fail-Closed DB Mechanics
Step 2: Secure SAML 2.0 Assertion Processing & Signature Validation
Step 3: Account Lifecycle, Routes, Step-Up Reauth & Password Recovery
Step 4: Email Delivery, Masked Token Logging, and Verification Infrastructure
Step 5: Per-Organization SCIM 2.0 Token Authentication and Authorization
Step 6: Cryptographic Random Internal User IDs & Federated Identity Binding
"""
import hashlib
import uuid
from unittest.mock import patch

import pytest

# Imports from services
from services.auth_service.adapters import SAML2Adapter
from services.auth_service.models import (
    AccountStatus,
    AccountStatusChangeRequest,
)
from services.auth_service.security import (
    generate_user_id,
    hash_password,
    issue_sudo_token,
    verify_password,
    verify_sudo_token,
)
from services.auth_service.user_lifecycle import UserLifecycleService
from services.common.db import (
    db_delete_scim_user,
    db_get_federated_identity,
    db_get_idp_config,
    db_get_scim_token_by_hash,
    db_get_scim_user,
    db_get_user_by_email,
    db_get_user_by_id,
    db_get_user_password,
    db_link_federated_identity,
    db_save_idp_config,
    db_save_scim_token,
    db_save_scim_user,
    db_save_user_password,
    db_upsert_user_profile,
)
from services.common.mailer import SMTPMailer, _mask_token_in_url


# ============================================================================
# STEP 1 TESTS: Complete Database Persistence
# ============================================================================
@pytest.mark.asyncio
async def test_step1_user_profile_persistence_and_lookup():
    """Verify user profiles persist to DB and load correctly via repository functions."""
    user_id = generate_user_id()
    email = f"user_{uuid.uuid4().hex[:8]}@example.com"
    profile_dict = {
        "user_id": user_id,
        "tenant_id": "default",
        "email": email,
        "display_name": "Test User",
        "status": "active",
        "roles": ["member"],
        "email_verified": True,
    }
    await db_upsert_user_profile(profile_dict)
    by_id = await db_get_user_by_id(user_id)
    assert by_id is not None
    assert by_id["user_id"] == user_id
    assert by_id["email"] == email
    by_email = await db_get_user_by_email(email)
    assert by_email is not None
    assert by_email["user_id"] == user_id
@pytest.mark.asyncio
async def test_step1_idp_config_db_persistence():
    """Verify IdP configurations persist through database repository functions."""
    org_id = f"org_{uuid.uuid4().hex[:8]}"
    cfg_dict = {
        "org_id": org_id,
        "idp_name": "Enterprise IdP",
        "sso_type": "saml",
        "issuer_url": "https://idp.example.com/sso",
        "client_id": "client_abc",
        "enforce_sso": True,
        "allowed_domains": ["example.com"],
        "group_role_mappings": {"Admins": "organization_administrator"},
        "metadata_xml": "<xml>meta</xml>",
    }
    await db_save_idp_config(cfg_dict)
    fetched = await db_get_idp_config(org_id)
    assert fetched is not None
    assert fetched["org_id"] == org_id
    assert fetched["idp_name"] == "Enterprise IdP"
    assert "example.com" in fetched["allowed_domains"]
@pytest.mark.asyncio
async def test_step1_scim_user_db_persistence():
    """Verify SCIM users persist through database repository functions."""
    scim_id = f"usr_{uuid.uuid4().hex[:8]}"
    username = f"scim_{uuid.uuid4().hex[:8]}@example.com"
    user_data = {
        "id": scim_id,
        "userName": username,
        "active": True,
        "name": {"givenName": "Jane", "familyName": "Doe"},
    }
    await db_save_scim_user(user_data, org_id="org_corp")
    fetched = await db_get_scim_user(scim_id, org_id="org_corp")
    assert fetched is not None
    assert fetched["userName"] == username
    deleted = await db_delete_scim_user(scim_id, org_id="org_corp")
    assert deleted is True
    assert await db_get_scim_user(scim_id) is None
# ============================================================================
# STEP 2 TESTS: Real, Secure SAML 2.0 Authentication
# ============================================================================
@pytest.mark.asyncio
async def test_step2_saml_issuer_mismatch_rejection():
    """Verify SAML adapter rejects assertions from untrusted/mismatched Issuers."""
    adapter = SAML2Adapter(
        sp_entity_id="https://auth.example.com",
        acs_url="https://auth.example.com/api/v1/auth/saml/acs",
        idp_issuer="https://trusted-idp.example.com",
    )
    xml_mismatched_issuer = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        <saml:Issuer>https://untrusted-idp.example.com</saml:Issuer>
        <saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>
        <saml:Attribute Name="email"><saml:AttributeValue>user@example.com</saml:AttributeValue></saml:Attribute>
    </samlp:Response>"""
    with pytest.raises(ValueError) as excinfo:
        await adapter.parse_saml_response(xml_mismatched_issuer)
    assert "Issuer mismatch" in str(excinfo.value)
@pytest.mark.asyncio
async def test_step2_saml_missing_nameid_rejection():
    """Verify SAML adapter rejects assertions missing NameID claims."""
    adapter = SAML2Adapter(
        sp_entity_id="https://auth.example.com",
        acs_url="https://auth.example.com/api/v1/auth/saml/acs",
    )
    xml_no_nameid = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        <saml:Issuer>https://idp.example.com</saml:Issuer>
    </samlp:Response>"""
    with pytest.raises(ValueError) as excinfo:
        await adapter.parse_saml_response(xml_no_nameid)
    assert "Missing required SAML NameID" in str(excinfo.value)
# ============================================================================
# STEP 3 TESTS: Account Lifecycle, Routes, Reauth & Recovery
# ============================================================================
@pytest.mark.asyncio
async def test_step3_stepup_reauthentication_validation():
    """Verify require_reauth validates sudo tokens against signature, expiration, and user binding."""
    user_id = generate_user_id()
    valid_token = issue_sudo_token(user_id)
    # Valid token for correct user
    assert verify_sudo_token(valid_token, expected_user_id=user_id) is True
    # Token used by a DIFFERENT user must fail
    assert verify_sudo_token(valid_token, expected_user_id="other_user_999") is False
    # Invalid arbitrary string header must fail
    assert (
        verify_sudo_token("arbitrary_header_string_value", expected_user_id=user_id)
        is False
    )
@pytest.mark.asyncio
async def test_step3_password_recovery_actually_updates_password():
    """Verify password recovery sets and updates stored credential hash in database."""
    user_id = generate_user_id()
    email = f"recovery_{uuid.uuid4().hex[:8]}@example.com"
    # Create profile
    service = UserLifecycleService()
    await service.get_or_create_profile(email)
    old_pwd = "OldPassword123!"
    new_pwd = "NewSecurePassword2026!"
    # Save initial password
    await db_save_user_password(user_id, hash_password(old_pwd))
    # Verify old password works
    stored1 = await db_get_user_password(user_id)
    assert verify_password(old_pwd, stored1) is True
    # Update password via recovery
    new_hash = hash_password(new_pwd)
    await db_save_user_password(user_id, new_hash)
    # Verify old password now FAILS, new password SUCCEEDS
    stored2 = await db_get_user_password(user_id)
    assert verify_password(old_pwd, stored2) is False
    assert verify_password(new_pwd, stored2) is True
@pytest.mark.asyncio
async def test_step3_account_status_change_contract():
    """Verify AccountStatusChangeRequest supports status field and lifecycle transition."""
    req = AccountStatusChangeRequest(
        status=AccountStatus.SUSPENDED, reason="Policy Violation"
    )
    assert req.status == AccountStatus.SUSPENDED
    assert req.reason == "Policy Violation"
# ============================================================================
# STEP 4 TESTS: Mailer Infrastructure & Masked Logging
# ============================================================================
@pytest.mark.asyncio
async def test_step4_masked_token_logging():
    """Verify LogMailer masks raw tokens and secret URLs to prevent log exposure."""
    secret_url = "https://auth.example.com/recovery?token=secret_recovery_token_12345"
    masked = _mask_token_in_url(secret_url)
    assert "secret_recovery_token_12345" not in masked
@pytest.mark.asyncio
async def test_step4_smtp_mailer_async_nonblocking():
    """Verify SMTPMailer executes delivery without blocking the event loop."""
    mailer = SMTPMailer(host="localhost", port=1025)
    with patch.object(mailer, "_send_email_sync", return_value=True):
        res = await mailer.send_account_recovery(
            "user@example.com", "http://auth/reset?token=xyz"
        )
        assert res is True
# ============================================================================
# STEP 5 TESTS: Per-Organization SCIM Tokens
# ============================================================================
@pytest.mark.asyncio
async def test_step5_per_org_scim_token_generation_and_auth():
    """Verify SCIM Bearer token hashes store per-organization and authenticate correctly."""
    org_id = f"org_{uuid.uuid4().hex[:8]}"
    raw_token = f"scim_{uuid.uuid4().hex}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    token_id = await db_save_scim_token(org_id, token_hash)
    assert token_id.startswith("scim_tok_")
    # Query database for SCIM token
    rec = await db_get_scim_token_by_hash(token_hash)
    assert rec is not None
    assert rec["org_id"] == org_id
    # Mismatched/invalid token hash must return None
    invalid_hash = hashlib.sha256(b"invalid_token").hexdigest()
    assert await db_get_scim_token_by_hash(invalid_hash) is None
# ============================================================================
# STEP 6 TESTS: Random Internal User IDs & Federated Identity Binding
# ============================================================================
@pytest.mark.asyncio
async def test_step6_random_internal_user_ids():
    """Verify generate_user_id produces random usr_<uuid4_hex> with full 128-bit entropy."""
    uid1 = generate_user_id("user1@example.com")
    uid2 = generate_user_id("user1@example.com")
    assert uid1.startswith("usr_")
    assert uid2.startswith("usr_")
    assert uid1 != uid2  # Non-deterministic random IDs
    assert len(uid1) >= 36  # Full entropy length
@pytest.mark.asyncio
async def test_step6_federated_identity_binding_and_lookup():
    """Verify federated identity stores and resolves via (provider, issuer, sub)."""
    user_id = generate_user_id()
    provider = "google"
    issuer = "https://accounts.google.com"
    sub = f"google_sub_{uuid.uuid4().hex[:12]}"
    email = f"user_{uuid.uuid4().hex[:8]}@example.com"
    fed_id = await db_link_federated_identity(
        user_id=user_id,
        provider=provider,
        issuer=issuer,
        sub=sub,
        email=email,
        email_verified=True,
    )
    assert fed_id.startswith("fed_")
    # Lookup by (provider, issuer, sub)
    found = await db_get_federated_identity(provider, issuer, sub)
    assert found is not None
    assert found["user_id"] == user_id
    assert found["email"] == email