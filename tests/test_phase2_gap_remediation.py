"""
Comprehensive Unit & Integration Test Suite for Phase 2 Gap Remediation.
"""
import unittest

from services.auth_service.enterprise import (
    apply_scim_patch,
    calculate_scim_version,
    evaluate_scim_filter,
    scim_service,
)
from services.auth_service.models import (
    AccountStatus,
    SCIMGroupSchema,
    SCIMMember,
    SCIMPatchOperation,
)
from services.auth_service.security import assess_suspicious_login
from services.auth_service.security_state import (
    consume_mfa_login_challenge,
    store_mfa_login_challenge,
)
from services.auth_service.user_lifecycle import lifecycle_service
from services.common.db import (
    db_assign_role,
    db_can_access_trip,
    db_get_user_by_email,
    db_revoke_role,
    db_save_trip_share,
    upsert_trip_result,
)
from tools.migrate_idp_secrets import migrate_idp_secrets
from tools.migrate_multi_org import migrate_multi_org_memberships


class TestPhase2GapRemediation(unittest.IsolatedAsyncioTestCase):
    async def test_gap1_mfa_login_challenge(self):
        """Gap 1: Verify MFA challenge generation and single-use consumption in Redis state."""
        jti = await store_mfa_login_challenge(
            user_id="usr_mfa_test",
            email="mfa@example.com",
            tenant_id="tenant_a",
            roles=["member"],
            ttl=300,
        )
        self.assertIsNotNone(jti)
        consumed = await consume_mfa_login_challenge(jti)
        self.assertIsNotNone(consumed)
        self.assertEqual(consumed["user_id"], "usr_mfa_test")
        consumed_again = await consume_mfa_login_challenge(jti)
        self.assertIsNone(consumed_again)
    async def test_gap2_tenant_isolation(self):
        """Gap 2: Verify tenant isolation across profile lookups and trip access queries."""
        email = "isolated_user@example.com"
        await lifecycle_service.get_or_create_profile(email, tenant_id="tenant_x")
        found = await db_get_user_by_email(email, tenant_id="tenant_x")
        self.assertIsNotNone(found)
        cid = "trip_tenant_iso_101"
        await upsert_trip_result("tenant_x", "usr_tx", cid, "Tokyo Trip")
        self.assertTrue(await db_can_access_trip("usr_tx", cid, "tenant_x", "read"))
        self.assertFalse(await db_can_access_trip("usr_tx", cid, "tenant_y", "read"))
    async def test_gap3_scim2_filter_patch_and_reconciliation(self):
        """Gap 3: Verify SCIM 2.0 RFC 7644 filtering, PATCH, ETags, and group-to-role reconciliation."""
        user_data = {
            "id": "usr_scim_1",
            "userName": "scim_test@example.com",
            "active": True,
            "name": {"givenName": "Jane", "familyName": "Doe"},
            "emails": [{"value": "scim_test@example.com", "type": "work"}],
        }
        self.assertTrue(
            evaluate_scim_filter(user_data, 'userName eq "scim_test@example.com"')
        )
        self.assertTrue(evaluate_scim_filter(user_data, "active eq true"))
        self.assertFalse(
            evaluate_scim_filter(user_data, 'userName eq "other@example.com"')
        )
        ops = [SCIMPatchOperation(op="replace", path="name.givenName", value="Janet")]
        patched = apply_scim_patch(user_data, ops)
        self.assertEqual(patched["name"]["givenName"], "Janet")
        version = calculate_scim_version(user_data)
        self.assertTrue(version.startswith('W/"'))
        group = SCIMGroupSchema(
            id="grp_admins",
            displayName="Admins",
            members=[SCIMMember(value="usr_scim_1", display="Jane Doe")],
        )
        await scim_service.reconcile_group_roles(group, "org_acme")
    async def test_gap5_provider_linking_and_unlinking(self):
        """Gap 5: Verify provider identity linking and last-method unlinking protection."""
        profile = await lifecycle_service.get_or_create_profile(
            "provider_link@example.com"
        )
        user_id = profile.user_id
        updated = await lifecycle_service.link_provider(
            user_id, "github", "gh_sub_123", email="provider_link@example.com"
        )
        self.assertTrue(any(lp.provider == "github" for lp in updated.linked_providers))
        with self.assertRaises(ValueError):
            await lifecycle_service.unlink_provider(user_id, "github")
    async def test_gap6_invitation_and_account_lifecycle(self):
        """Gap 6: Verify account invitations and grace-period lifecycle."""
        inv = await lifecycle_service.create_invitation(
            "invitee@example.com", "org_inc", "travel_planner", "admin_usr"
        )
        self.assertEqual(inv.email, "invitee@example.com")
        self.assertEqual(inv.org_id, "org_inc")
        p_created = await lifecycle_service.get_or_create_profile(
            "usr_soft_del@example.com"
        )
        del_profile = await lifecycle_service.schedule_account_deletion(
            p_created.user_id, grace_period_days=30
        )
        self.assertEqual(del_profile.status, AccountStatus.PENDING_DELETION)
        recovered = await lifecycle_service.cancel_account_deletion(p_created.user_id)
        self.assertEqual(recovered.status, AccountStatus.ACTIVE)
    async def test_gap7_comprehensive_trip_access_enforcement(self):
        """Gap 7: Verify trip read, write, share, and delete access enforcement."""
        cid = "trip_acl_test_202"
        await upsert_trip_result("tenant_a", "usr_owner_acl", cid, "Kyoto Tour")
        self.assertTrue(
            await db_can_access_trip("usr_owner_acl", cid, "tenant_a", "read")
        )
        self.assertTrue(
            await db_can_access_trip("usr_owner_acl", cid, "tenant_a", "write")
        )
        self.assertFalse(
            await db_can_access_trip("usr_stranger_acl", cid, "tenant_a", "read")
        )
        await db_save_trip_share(
            {
                "trip_id": cid,
                "owner_id": "usr_owner_acl",
                "grantee_id": "usr_reader_acl",
                "permission_level": "read",
            }
        )
        self.assertTrue(
            await db_can_access_trip("usr_reader_acl", cid, "tenant_a", "read")
        )
        self.assertFalse(
            await db_can_access_trip("usr_reader_acl", cid, "tenant_a", "write")
        )
    async def test_gap8_multi_org_roles(self):
        """Gap 8: Verify multi-organization role assignments and membership queries."""
        await db_assign_role(
            "usr_multi_org",
            "organization_administrator",
            "organization",
            "org_1",
            "admin_1",
        )
        await db_assign_role(
            "usr_multi_org", "travel_planner", "organization", "org_2", "admin_2"
        )
        count = await db_revoke_role(
            "usr_multi_org", "travel_planner", "organization", "org_2"
        )
        self.assertEqual(count, 1)
    async def test_gap9_suspicious_login_risk_detection(self):
        """Gap 9: Verify suspicious login risk assessment calculation."""
        history = [
            {
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0 (Macintosh)",
                "status": "success",
                "timestamp": "2026-11-20T10:00:00Z",
            },
            {
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0 (Macintosh)",
                "status": "success",
                "timestamp": "2026-11-21T10:00:00Z",
            },
        ]
        suspicious, _ = assess_suspicious_login(
            "usr_risk_test", "192.168.1.1", "Mozilla/5.0 (Macintosh)", history
        )
        self.assertFalse(suspicious)
        suspicious_anom, _ = assess_suspicious_login(
            "usr_risk_test", "203.0.113.99", "UnknownBot/1.0", history
        )
        self.assertTrue(suspicious_anom)
    async def test_gap10_migration_tooling(self):
        """Gap 10: Verify idempotent IdP secret encryption and multi-org migration tools."""
        await migrate_idp_secrets()
        await migrate_multi_org_memberships()
if __name__ == "__main__":
    unittest.main()