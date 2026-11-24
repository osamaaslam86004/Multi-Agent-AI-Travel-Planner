#!/usr/bin/env python3
"""
Production Data Migration Tool: Backfill Multi-Organization Memberships & Roles.
Backfills org_memberships and role_assignments tables from legacy single-org profiles.
"""

import asyncio
import logging

from services.common.db import (
    db_add_org_membership,
    db_assign_role,
    init_db_pool,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tools.migrate_multi_org")


async def migrate_multi_org_memberships():
    logger.info("Starting Multi-Organization Memberships and Roles backfill...")
    pool = await init_db_pool()
    if pool is None:
        logger.info("Database pool unavailable; skipping live SQL backfill.")
        return
    count = 0
    async with pool.connection() as conn, conn.cursor() as cur:
        await cur.execute(
            "SELECT user_id, org_id, roles FROM user_profiles WHERE org_id IS NOT NULL;"
        )
        rows = await cur.fetchall()
        for r in rows:
            user_id, org_id, roles_raw = r[0], r[1], r[2]
            roles = roles_raw if isinstance(roles_raw, list) else []
            role = roles[0] if roles else "member"
            await db_add_org_membership(user_id, org_id, role)
            await db_assign_role(
                user_id, role, "organization", org_id, "migration_backfill"
            )
            count += 1
    logger.info(
        f"Multi-Org Migration complete. Backfilled {count} organization memberships."
    )


if __name__ == "__main__":
    asyncio.run(migrate_multi_org_memberships())
