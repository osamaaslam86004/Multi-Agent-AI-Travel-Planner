"""
CLI & Seed Tool: Bootstrap Organization & Initial Platform Owner.
Creates the default org row and assigns initial platform owner privileges.
"""

import asyncio
import logging

from services.common.db import (
    db_assign_role,
    db_upsert_user_profile,
    init_db_pool,
    init_identity_schema,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tools.bootstrap_org")


async def bootstrap_org(
    org_id: str = "org_default",
    org_name: str = "Default Organization",
    owner_email: str = "admin@travelbrain.ai",
    owner_name: str = "Platform Owner",
    tenant_id: str = "default",
) -> dict[str, str]:
    logger.info(f"Initializing identity schema and bootstrapping org '{org_id}'...")
    pool = await init_db_pool()
    if pool is not None:
        async with pool.connection() as conn:
            await init_identity_schema(conn)
            async with conn.transaction(), conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO orgs (org_id, org_name) "
                    "VALUES (%s, %s) "
                    "ON CONFLICT (org_id) DO UPDATE SET org_name = EXCLUDED.org_name;",
                    (org_id, org_name),
                )
        logger.info(f"Created/verified organization '{org_id}' ({org_name})")
    # Create platform owner profile
    user_id = f"usr_admin_{org_id}"
    profile_dict = {
        "user_id": user_id,
        "tenant_id": tenant_id,
        "org_id": org_id,
        "email": owner_email,
        "display_name": owner_name,
        "status": "active",
        "roles": ["platform_owner", "organization_owner"],
        "email_verified": True,
    }
    await db_upsert_user_profile(profile_dict)
    await db_assign_role(
        user_id, "platform_owner", "platform", None, "system_bootstrap"
    )
    await db_assign_role(
        user_id, "organization_owner", "organization", org_id, "system_bootstrap"
    )
    logger.info(
        f"Successfully bootstrapped platform owner '{user_id}' ({owner_email}) for org '{org_id}'"
    )
    return {"org_id": org_id, "user_id": user_id, "email": owner_email}


if __name__ == "__main__":
    asyncio.run(bootstrap_org())
