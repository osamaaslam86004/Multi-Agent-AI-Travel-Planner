"""
Postgres Database connection pool management, tenant RLS context setting,
and transactional operations for trips, append-only event audit, LLM usage ledger, outbox,
and Phase 2 identity schema persistence.
"""

import contextlib
import json
import logging
from collections.abc import AsyncGenerator
from typing import Any

try:
    import psycopg
    from psycopg_pool import AsyncConnectionPool

    _PSYCOPG_ERRORS = (psycopg.Error,)
except ImportError:
    psycopg = None
    AsyncConnectionPool = None
    _PSYCOPG_ERRORS = (Exception,)

from services.core.config import get_settings

logger = logging.getLogger("travelbrain.db")


def _get_db_settings():
    return get_settings().db


_DB_ERRORS: tuple[type[Exception], ...] = _PSYCOPG_ERRORS + (
    ImportError,
    OSError,
    RuntimeError,
    ValueError,
    json.JSONDecodeError,
)
_pool: Any = None
_in_memory_db: dict[str, Any] = {
    "trips": {},
    "trip_events": [],
    "llm_usage": [],
    "outbox": [],
    "user_profiles": {},
    "federated_identities": [],
    "login_history": [],
    "orgs": {},
    "org_memberships": [],
    "role_assignments": [],
    "idp_configs": {},
    "scim_tokens": {},
    "scim_groups": {},
}


async def init_identity_schema(conn: Any) -> None:
    """Step 2 (C-8): DDL migration helper initializing Phase 2 Identity tables if not present."""
    ddl = """
    CREATE TABLE IF NOT EXISTS orgs (
        org_id VARCHAR(64) PRIMARY KEY,
        org_name VARCHAR(255) NOT NULL,
        allowed_domains JSONB DEFAULT '[]'::jsonb,
        enforce_sso BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS user_profiles (
        user_id VARCHAR(64) PRIMARY KEY,
        tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
        org_id VARCHAR(64) REFERENCES orgs(org_id) ON DELETE SET NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        display_name VARCHAR(255),
        avatar_url TEXT,
        bio TEXT,
        timezone VARCHAR(50) DEFAULT 'UTC',
        preferred_currency VARCHAR(10) DEFAULT 'USD',
        status VARCHAR(32) NOT NULL DEFAULT 'active',
        roles JSONB DEFAULT '["member"]'::jsonb,
        email_verified BOOLEAN DEFAULT FALSE,
        mfa_enabled BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS federated_identities (
        id VARCHAR(64) PRIMARY KEY,
        user_id VARCHAR(64) NOT NULL REFERENCES user_profiles(user_id) ON DELETE CASCADE,
        provider VARCHAR(64) NOT NULL,
        issuer TEXT NOT NULL,
        sub TEXT NOT NULL,
        email VARCHAR(255),
        email_verified BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(provider, issuer, sub)
    );

    CREATE TABLE IF NOT EXISTS login_history (
        id VARCHAR(64) PRIMARY KEY,
        user_id VARCHAR(64) NOT NULL REFERENCES user_profiles(user_id) ON DELETE CASCADE,
        provider VARCHAR(64) NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        user_agent TEXT NOT NULL,
        status VARCHAR(32) NOT NULL,
        suspicious BOOLEAN DEFAULT FALSE,
        details TEXT,
        timestamp TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS org_memberships (
        user_id VARCHAR(64) REFERENCES user_profiles(user_id) ON DELETE CASCADE,
        org_id VARCHAR(64) REFERENCES orgs(org_id) ON DELETE CASCADE,
        role VARCHAR(64) NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        PRIMARY KEY (user_id, org_id)
    );

    CREATE TABLE IF NOT EXISTS role_assignments (
        id VARCHAR(64) PRIMARY KEY,
        user_id VARCHAR(64) REFERENCES user_profiles(user_id) ON DELETE CASCADE,
        role VARCHAR(64) NOT NULL,
        scope_type VARCHAR(32) NOT NULL,
        scope_id VARCHAR(64),
        assigned_by VARCHAR(64),
        created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS idp_configs (
        org_id VARCHAR(64) PRIMARY KEY REFERENCES orgs(org_id) ON DELETE CASCADE,
        idp_name VARCHAR(100) NOT NULL,
        sso_type VARCHAR(32) NOT NULL,
        issuer_url TEXT NOT NULL,
        client_id TEXT NOT NULL,
        client_secret TEXT,
        metadata_xml TEXT,
        enforce_sso BOOLEAN DEFAULT FALSE,
        allowed_domains JSONB DEFAULT '[]'::jsonb,
        group_role_mappings JSONB DEFAULT '{}'::jsonb,
        updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS scim_tokens (
        token_id VARCHAR(64) PRIMARY KEY,
        org_id VARCHAR(64) REFERENCES orgs(org_id) ON DELETE CASCADE,
        token_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS scim_groups (
        group_id VARCHAR(64) PRIMARY KEY,
        org_id VARCHAR(64) REFERENCES orgs(org_id) ON DELETE CASCADE,
        display_name VARCHAR(255) NOT NULL,
        members JSONB DEFAULT '[]'::jsonb,
        created_at TIMESTAMPTZ DEFAULT NOW()
    );
    """
    async with conn.cursor() as cur:
        await cur.execute(ddl)
    await conn.commit()


async def init_db_pool() -> Any:
    global _pool
    if _pool is not None:
        return _pool
    if psycopg is None or AsyncConnectionPool is None:
        _pool = None
        return None
    try:
        db_cfg = _get_db_settings()
        conn_str = (
            f"postgresql://{db_cfg.user}:{db_cfg.password}@"
            f"{db_cfg.host}:{db_cfg.port}/{db_cfg.db_name}"
        )
        _pool = AsyncConnectionPool(
            conninfo=conn_str, min_size=1, max_size=10, open=False
        )
        await _pool.open()
        logger.info("Initialized Postgres connection pool.")
        async with _pool.connection() as conn:
            await init_identity_schema(conn)
        return _pool
    except (ImportError, OSError, RuntimeError, ValueError, Exception) as exc:
        logger.warning(
            f"Postgres pool initialization unavailable: {exc}. Using fallback in-memory database store."
        )
        _pool = None
        return None


async def close_db_pool() -> None:
    global _pool
    if _pool is not None:
        try:
            await _pool.close()
        except _DB_ERRORS as exc:
            logger.debug(f"Error closing Postgres pool: {exc}")
        _pool = None


@contextlib.asynccontextmanager
async def get_tenant_conn(tenant_id: str = "default") -> AsyncGenerator[Any, None]:
    pool = await init_db_pool()
    if pool is None:
        yield None
        return
    try:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("SET LOCAL app.current_tenant_id = %s;", (tenant_id,))
            yield conn
    except _DB_ERRORS as exc:
        logger.warning(
            f"Error getting database connection for tenant '{tenant_id}': {exc}"
        )
        yield None


async def write_outbox(
    tenant_id: str,
    correlation_id: str,
    stream_name: str,
    event_type: str,
    payload: dict[str, Any],
) -> str:
    """Step 1 (A-1): Positionally compatible write_outbox inserting real profile reference."""
    async with get_tenant_conn(tenant_id) as conn:
        if conn:
            try:
                async with conn.transaction(), conn.cursor() as cur:
                    user_id = payload.get("user_id", "guest")
                    email = payload.get("email") or f"{user_id}@{tenant_id}.local"
                    await cur.execute(
                        "INSERT INTO user_profiles (user_id, tenant_id, email, status) "
                        "VALUES (%s, %s, %s, 'active') "
                        "ON CONFLICT (user_id) DO NOTHING;",
                        (user_id, tenant_id, email),
                    )
                    trip_id = f"trip_{correlation_id}"
                    query = payload.get("user_query", "")
                    await cur.execute(
                        "INSERT INTO trips (trip_id, tenant_id, user_id, correlation_id, user_query, status) "
                        "VALUES (%s, %s, %s, %s, %s, 'GATHERING') "
                        "ON CONFLICT (correlation_id) DO NOTHING;",
                        (trip_id, tenant_id, user_id, correlation_id, query),
                    )
                    await cur.execute(
                        "INSERT INTO outbox (tenant_id, correlation_id, stream_name, event_type, payload) "
                        "VALUES (%s, %s, %s, %s, %s::jsonb);",
                        (
                            tenant_id,
                            correlation_id,
                            stream_name,
                            event_type,
                            json.dumps(payload),
                        ),
                    )
                logger.info(
                    f"Outbox entry written for correlation_id '{correlation_id}'"
                )
            except _DB_ERRORS as exc:
                logger.error(f"Failed writing outbox entry: {exc}")
    _in_memory_db["outbox"].append(
        {
            "tenant_id": tenant_id,
            "correlation_id": correlation_id,
            "stream_name": stream_name,
            "event_type": event_type,
            "payload": payload,
            "processed": False,
        }
    )
    _in_memory_db["trips"][correlation_id] = {
        "correlation_id": correlation_id,
        "tenant_id": tenant_id,
        "user_id": payload.get("user_id", "guest"),
        "user_query": payload.get("user_query", ""),
        "status": "GATHERING",
    }
    return correlation_id


async def relay_outbox(event_bus: Any) -> int:
    relayed_count = 0
    pool = await init_db_pool()
    if pool:
        try:
            async with pool.connection() as conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT id, tenant_id, correlation_id, stream_name, event_type, payload "
                        "FROM outbox WHERE processed = FALSE ORDER BY created_at ASC LIMIT 50 FOR UPDATE SKIP LOCKED;"
                    )
                    rows = await cur.fetchall()
                    for row in rows:
                        outbox_id, _tenant_id, cid, stream, event_type, payload = row
                        if isinstance(payload, str):
                            payload = json.loads(payload)
                        from services.common.schemas import CloudEvent

                        ce = CloudEvent[Any](
                            source="/services/outbox-relay",
                            type=event_type,
                            subject=cid,
                            data=payload,
                        )
                        await event_bus.publish(stream, ce)
                        await cur.execute(
                            "UPDATE outbox SET processed = TRUE, processed_at = NOW() WHERE id = %s;",
                            (outbox_id,),
                        )
                        relayed_count += 1
                await conn.commit()
        except _DB_ERRORS as exc:
            logger.debug(f"Outbox relay DB poll exception: {exc}")
    for item in _in_memory_db["outbox"]:
        if not item["processed"]:
            from services.common.schemas import CloudEvent

            ce = CloudEvent[Any](
                source="/services/outbox-relay",
                type=item["event_type"],
                subject=item["correlation_id"],
                data=item["payload"],
            )
            await event_bus.publish(item["stream_name"], ce)
            item["processed"] = True
            relayed_count += 1
    return relayed_count
