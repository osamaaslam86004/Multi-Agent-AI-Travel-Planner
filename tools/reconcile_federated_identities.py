#!/usr/bin/env python3
"""
Production Data Migration Tool: Reconcile Federated Identity Records.
Reconciles federated identity records with user profile email addresses.
"""

import asyncio
import logging

from services.common.db import init_db_pool

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tools.reconcile_federated_identities")


async def reconcile_federated_identities():
    logger.info("Starting Federated Identity reconciliation...")
    pool = await init_db_pool()
    if pool is None:
        logger.info("Database pool unavailable; skipping SQL reconciliation.")
        return
    count = 0
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute(
                "UPDATE federated_identities fi SET email = up.email "
                "FROM user_profiles up WHERE fi.user_id = up.user_id "
                "AND (fi.email IS NULL OR fi.email != up.email);"
            )
            count = cur.rowcount
        await conn.commit()
    logger.info(f"Federated Identity reconciliation complete. Updated {count} records.")


if __name__ == "__main__":
    asyncio.run(reconcile_federated_identities())
