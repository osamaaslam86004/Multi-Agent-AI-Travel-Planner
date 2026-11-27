#!/usr/bin/env python3
"""
Production Data Migration Tool: Encrypt Plaintext IdP Client Secrets.
Idempotent script to safely migrate plaintext client_secret entries in idp_configs to ciphertext ('enc:v1:...').
"""

import asyncio
import logging

from services.auth_service.enterprise import enterprise_service
from services.common.db import db_list_all_idp_configs, db_save_idp_config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("tools.migrate_idp_secrets")


async def migrate_idp_secrets():
    logger.info("Starting IdP Client Secrets encryption migration...")
    configs = await db_list_all_idp_configs()
    count = 0
    for cfg in configs:
        secret = cfg.get("client_secret")
        if secret and not secret.startswith("enc:v1:"):
            logger.info(f"Encrypting secret for organization '{cfg['org_id']}'...")
            encrypted = enterprise_service._encrypt_client_secret(secret)
            cfg["client_secret"] = encrypted
            await db_save_idp_config(cfg)
            count += 1
    logger.info(
        f"IdP Client Secrets migration complete. Encrypted {count} plaintext records."
    )


if __name__ == "__main__":
    asyncio.run(migrate_idp_secrets())
