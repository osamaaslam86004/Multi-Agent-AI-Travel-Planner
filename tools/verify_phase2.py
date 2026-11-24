#!/usr/bin/env python3
"""
Phase 2 Integration Validation Harness & End-to-End Smoke Test Runner.
"""
import asyncio
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verify_phase2")
async def test_scim_filter_and_patch():
    logger.info("[Test 1/5] Validating SCIM 2.0 Filter & PATCH Engine...")
    from services.auth_service.enterprise import apply_scim_patch, evaluate_scim_filter
    from services.auth_service.models import SCIMPatchOperation
    user = {
        "userName": "alice@example.com",
        "active": True,
        "name": {"givenName": "Alice", "familyName": "Smith"},
    }
    assert evaluate_scim_filter(user, 'userName eq "alice@example.com"') is True
    ops = [SCIMPatchOperation(op="replace", path="active", value=False)]
    patched = apply_scim_patch(user, ops)
    assert patched["active"] is False
    logger.info("-> SCIM 2.0 Filter & PATCH: PASS")
async def test_trip_access_control():
    logger.info("[Test 2/5] Validating Trip ACL & Tenant Isolation...")
    from services.common.db import (
        db_can_access_trip,
        db_save_trip_share,
        upsert_trip_result,
    )
    cid = "test_acl_trip_101"
    await upsert_trip_result(
        tenant_id="tenant_alpha",
        user_id="usr_owner",
        correlation_id=cid,
        user_query="Paris trip",
    )
    assert await db_can_access_trip("usr_owner", cid, "tenant_alpha", "read") is True
    assert (
        await db_can_access_trip("usr_stranger", cid, "tenant_alpha", "read") is False
    )
    await db_save_trip_share(
        {
            "trip_id": cid,
            "owner_id": "usr_owner",
            "grantee_id": "usr_collaborator",
            "permission_level": "read",
        }
    )
    assert (
        await db_can_access_trip("usr_collaborator", cid, "tenant_alpha", "read")
        is True
    )
    logger.info("-> Trip ACL: PASS")
async def test_invitation_and_lifecycle():
    logger.info("[Test 3/5] Validating Account Invitation...")
    from services.auth_service.user_lifecycle import lifecycle_service
    inv = await lifecycle_service.create_invitation(
        "invited@example.com", "org_acme", "travel_planner", "admin_1"
    )
    assert inv.token is not None
    logger.info("-> Invitation: PASS")
async def test_migration_scripts():
    logger.info("[Test 4/4] Validating Migration Tools...")
    from tools.migrate_idp_secrets import migrate_idp_secrets
    from tools.migrate_multi_org import migrate_multi_org_memberships
    await migrate_idp_secrets()
    await migrate_multi_org_memberships()
    logger.info("-> Migration Tools: PASS")
async def run_harness():
    logger.info("=== Phase 2 Integration Validation Harness ===")
    await test_scim_filter_and_patch()
    await test_trip_access_control()
    await test_invitation_and_lifecycle()
    await test_migration_scripts()
    logger.info("=== ALL PHASE 2 INTEGRATION TESTS PASSED ===")
if __name__ == "__main__":
    asyncio.run(run_harness())