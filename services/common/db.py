"""
Postgres Database connection pool management, tenant RLS context setting,
and transactional operations for trips, append-only event audit, LLM usage ledger, outbox,
and Phase 2 identity schema persistence.
"""

import contextlib
import json
import logging
import uuid
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
    "scim_users": {},
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
    CREATE TABLE IF NOT EXISTS scim_users (
        scim_id VARCHAR(64) PRIMARY KEY,
        user_name VARCHAR(255) NOT NULL UNIQUE,
        given_name VARCHAR(255),
        family_name VARCHAR(255),
        active BOOLEAN DEFAULT TRUE,
        raw_payload JSONB NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
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


# --- Identity Repository DB Persistence Functions (Action Item 1) ---


async def db_get_user_by_email(email: str) -> dict[str, Any] | None:
    email_clean = email.lower().strip()
    async with get_tenant_conn() as conn:
        if conn:
            try:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT user_id, tenant_id, org_id, email, display_name, avatar_url, bio, timezone, "
                        "preferred_currency, status, roles, email_verified, mfa_enabled, created_at, updated_at "
                        "FROM user_profiles WHERE LOWER(email) = %s;",
                        (email_clean,),
                    )
                    row = await cur.fetchone()
                    if row:
                        return {
                            "user_id": row[0],
                            "tenant_id": row[1],
                            "org_id": row[2],
                            "email": row[3],
                            "display_name": row[4],
                            "avatar_url": row[5],
                            "bio": row[6],
                            "timezone": row[7],
                            "preferred_currency": row[8],
                            "status": row[9],
                            "roles": json.loads(row[10])
                            if isinstance(row[10], str)
                            else row[10],
                            "email_verified": row[11],
                            "mfa_enabled": row[12],
                            "created_at": str(row[13]),
                            "updated_at": str(row[14]),
                        }
            except _DB_ERRORS as exc:
                logger.error(f"Error fetching user by email from DB: {exc}")
    for u in _in_memory_db["user_profiles"].values():
        if u.get("email", "").lower() == email_clean:
            return u
    return None


async def db_get_user_by_id(user_id: str) -> dict[str, Any] | None:
    async with get_tenant_conn() as conn:
        if conn:
            try:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT user_id, tenant_id, org_id, email, display_name, avatar_url, bio, timezone, "
                        "preferred_currency, status, roles, email_verified, mfa_enabled, created_at, updated_at "
                        "FROM user_profiles WHERE user_id = %s;",
                        (user_id,),
                    )
                    row = await cur.fetchone()
                    if row:
                        return {
                            "user_id": row[0],
                            "tenant_id": row[1],
                            "org_id": row[2],
                            "email": row[3],
                            "display_name": row[4],
                            "avatar_url": row[5],
                            "bio": row[6],
                            "timezone": row[7],
                            "preferred_currency": row[8],
                            "status": row[9],
                            "roles": json.loads(row[10])
                            if isinstance(row[10], str)
                            else row[10],
                            "email_verified": row[11],
                            "mfa_enabled": row[12],
                            "created_at": str(row[13]),
                            "updated_at": str(row[14]),
                        }
            except _DB_ERRORS as exc:
                logger.error(f"Error fetching user by ID from DB: {exc}")
    return _in_memory_db["user_profiles"].get(user_id)


async def db_upsert_user_profile(user_dict: dict[str, Any]) -> None:
    user_id = user_dict["user_id"]
    tenant_id = user_dict.get("tenant_id", "default")
    email = user_dict["email"].lower().strip()
    display_name = user_dict.get("display_name")
    avatar_url = user_dict.get("avatar_url")
    bio = user_dict.get("bio")
    timezone = user_dict.get("timezone", "UTC")
    preferred_currency = user_dict.get("preferred_currency", "USD")
    status = user_dict.get("status", "active")
    roles = json.dumps(user_dict.get("roles", ["member"]))
    email_verified = user_dict.get("email_verified", False)
    mfa_enabled = user_dict.get("mfa_enabled", False)
    org_id = user_dict.get("org_id")

    async with get_tenant_conn(tenant_id) as conn:
        if conn:
            try:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO user_profiles (user_id, tenant_id, org_id, email, display_name, avatar_url, bio, timezone, preferred_currency, status, roles, email_verified, mfa_enabled) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s) "
                        "ON CONFLICT (user_id) DO UPDATE SET "
                        "display_name = EXCLUDED.display_name, avatar_url = EXCLUDED.avatar_url, bio = EXCLUDED.bio, "
                        "timezone = EXCLUDED.timezone, preferred_currency = EXCLUDED.preferred_currency, status = EXCLUDED.status, "
                        "roles = EXCLUDED.roles, email_verified = EXCLUDED.email_verified, mfa_enabled = EXCLUDED.mfa_enabled, "
                        "updated_at = NOW();",
                        (
                            user_id,
                            tenant_id,
                            org_id,
                            email,
                            display_name,
                            avatar_url,
                            bio,
                            timezone,
                            preferred_currency,
                            status,
                            roles,
                            email_verified,
                            mfa_enabled,
                        ),
                    )
            except _DB_ERRORS as exc:
                logger.error(f"Error upserting user profile in DB: {exc}")

    _in_memory_db["user_profiles"][user_id] = user_dict


# Federated Identities (Action Item 6 & Item 1)
async def db_link_federated_identity(
    user_id: str,
    provider: str,
    issuer: str,
    sub: str,
    email: str | None = None,
    email_verified: bool = False,
) -> str:
    fed_id = f"fed_{uuid.uuid4().hex[:12]}"
    async with get_tenant_conn() as conn:
        if conn:
            try:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO federated_identities (id, user_id, provider, issuer, sub, email, email_verified) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s) "
                        "ON CONFLICT (provider, issuer, sub) DO UPDATE SET email = EXCLUDED.email, email_verified = EXCLUDED.email_verified;",
                        (fed_id, user_id, provider, issuer, sub, email, email_verified),
                    )
            except _DB_ERRORS as exc:
                logger.error(f"Error linking federated identity in DB: {exc}")
    _in_memory_db["federated_identities"].append(
        {
            "id": fed_id,
            "user_id": user_id,
            "provider": provider,
            "issuer": issuer,
            "sub": sub,
            "email": email,
            "email_verified": email_verified,
        }
    )
    return fed_id


async def db_get_federated_identity(
    provider: str, issuer: str, sub: str
) -> dict[str, Any] | None:
    async with get_tenant_conn() as conn:
        if conn:
            try:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT id, user_id, provider, issuer, sub, email, email_verified FROM federated_identities "
                        "WHERE provider = %s AND issuer = %s AND sub = %s;",
                        (provider, issuer, sub),
                    )
                    row = await cur.fetchone()
                    if row:
                        return {
                            "id": row[0],
                            "user_id": row[1],
                            "provider": row[2],
                            "issuer": row[3],
                            "sub": row[4],
                            "email": row[5],
                            "email_verified": row[6],
                        }
            except _DB_ERRORS as exc:
                logger.error(f"Error getting federated identity from DB: {exc}")
    for fi in _in_memory_db["federated_identities"]:
        if fi["provider"] == provider and fi["issuer"] == issuer and fi["sub"] == sub:
            return fi
    return None


# SCIM Per-Org Token Repository (Action Item 5)
async def db_save_scim_token(org_id: str, token_hash: str) -> str:
    token_id = f"scim_tok_{uuid.uuid4().hex[:12]}"
    async with get_tenant_conn() as conn:
        if conn:
            try:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO scim_tokens (token_id, org_id, token_hash) VALUES (%s, %s, %s);",
                        (token_id, org_id, token_hash),
                    )
            except _DB_ERRORS as exc:
                logger.error(f"Error saving SCIM token in DB: {exc}")
    _in_memory_db["scim_tokens"][token_id] = {
        "token_id": token_id,
        "org_id": org_id,
        "token_hash": token_hash,
    }
    return token_id


async def db_get_scim_token_by_hash(token_hash: str) -> dict[str, Any] | None:
    async with get_tenant_conn() as conn:
        if conn:
            try:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT token_id, org_id, token_hash FROM scim_tokens WHERE token_hash = %s;",
                        (token_hash,),
                    )
                    row = await cur.fetchone()
                    if row:
                        return {
                            "token_id": row[0],
                            "org_id": row[1],
                            "token_hash": row[2],
                        }
            except _DB_ERRORS as exc:
                logger.error(f"Error fetching SCIM token by hash from DB: {exc}")
    for tok in _in_memory_db["scim_tokens"].values():
        if tok["token_hash"] == token_hash:
            return tok
    return None


# IdP Config Database Repository Functions (Action Item 1)
async def db_get_idp_config(org_id: str) -> dict[str, Any] | None:
    async with get_tenant_conn() as conn:
        if conn:
            try:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT org_id, idp_name, sso_type, issuer_url, client_id, enforce_sso, allowed_domains, group_role_mappings, metadata_xml "
                        "FROM idp_configs WHERE org_id = %s;",
                        (org_id,),
                    )
                    row = await cur.fetchone()
                    if row:
                        return {
                            "org_id": row[0],
                            "idp_name": row[1],
                            "sso_type": row[2],
                            "issuer_url": row[3],
                            "client_id": row[4],
                            "enforce_sso": row[5],
                            "allowed_domains": json.loads(row[6])
                            if isinstance(row[6], str)
                            else row[6],
                            "group_role_mappings": json.loads(row[7])
                            if isinstance(row[7], str)
                            else row[7],
                            "metadata_xml": row[8],
                        }
            except _DB_ERRORS as exc:
                logger.error(f"Error getting IdP config from DB: {exc}")
    return _in_memory_db["idp_configs"].get(org_id)


async def db_save_idp_config(cfg_dict: dict[str, Any]) -> None:
    org_id = cfg_dict["org_id"]
    async with get_tenant_conn() as conn:
        if conn:
            try:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO orgs (org_id, org_name, allowed_domains, enforce_sso) "
                        "VALUES (%s, %s, %s::jsonb, %s) ON CONFLICT (org_id) DO NOTHING;",
                        (
                            org_id,
                            f"Org {org_id}",
                            json.dumps(cfg_dict.get("allowed_domains", [])),
                            cfg_dict.get("enforce_sso", False),
                        ),
                    )
                    await cur.execute(
                        "INSERT INTO idp_configs (org_id, idp_name, sso_type, issuer_url, client_id, enforce_sso, allowed_domains, group_role_mappings, metadata_xml) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s) "
                        "ON CONFLICT (org_id) DO UPDATE SET idp_name = EXCLUDED.idp_name, sso_type = EXCLUDED.sso_type, "
                        "issuer_url = EXCLUDED.issuer_url, client_id = EXCLUDED.client_id, enforce_sso = EXCLUDED.enforce_sso, "
                        "allowed_domains = EXCLUDED.allowed_domains, group_role_mappings = EXCLUDED.group_role_mappings, "
                        "metadata_xml = EXCLUDED.metadata_xml, updated_at = NOW();",
                        (
                            org_id,
                            cfg_dict["idp_name"],
                            cfg_dict["sso_type"],
                            cfg_dict["issuer_url"],
                            cfg_dict["client_id"],
                            cfg_dict.get("enforce_sso", False),
                            json.dumps(cfg_dict.get("allowed_domains", [])),
                            json.dumps(cfg_dict.get("group_role_mappings", {})),
                            cfg_dict.get("metadata_xml"),
                        ),
                    )
            except _DB_ERRORS as exc:
                logger.error(f"Error saving IdP config in DB: {exc}")
    _in_memory_db["idp_configs"][org_id] = cfg_dict


async def db_list_all_idp_configs() -> list[dict[str, Any]]:
    configs = []
    async with get_tenant_conn() as conn:
        if conn:
            try:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT org_id, idp_name, sso_type, issuer_url, client_id, enforce_sso, allowed_domains, group_role_mappings, metadata_xml FROM idp_configs;"
                    )
                    rows = await cur.fetchall()
                    for row in rows:
                        configs.append(
                            {
                                "org_id": row[0],
                                "idp_name": row[1],
                                "sso_type": row[2],
                                "issuer_url": row[3],
                                "client_id": row[4],
                                "enforce_sso": row[5],
                                "allowed_domains": json.loads(row[6])
                                if isinstance(row[6], str)
                                else row[6],
                                "group_role_mappings": json.loads(row[7])
                                if isinstance(row[7], str)
                                else row[7],
                                "metadata_xml": row[8],
                            }
                        )
                    return configs
            except _DB_ERRORS as exc:
                logger.error(f"Error listing IdP configs from DB: {exc}")
    return list(_in_memory_db["idp_configs"].values())


# SCIM Users Repository Functions
async def db_save_scim_user(user_data: dict[str, Any]) -> None:
    scim_id = user_data["id"]
    user_name = user_data["userName"]
    name_obj = user_data.get("name") or {}
    given_name = name_obj.get("givenName") if isinstance(name_obj, dict) else None
    family_name = name_obj.get("familyName") if isinstance(name_obj, dict) else None
    active = user_data.get("active", True)
    raw_payload = json.dumps(user_data)

    async with get_tenant_conn() as conn:
        if conn:
            try:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO scim_users (scim_id, user_name, given_name, family_name, active, raw_payload) "
                        "VALUES (%s, %s, %s, %s, %s, %s::jsonb) "
                        "ON CONFLICT (scim_id) DO UPDATE SET user_name = EXCLUDED.user_name, given_name = EXCLUDED.given_name, "
                        "family_name = EXCLUDED.family_name, active = EXCLUDED.active, raw_payload = EXCLUDED.raw_payload, updated_at = NOW();",
                        (
                            scim_id,
                            user_name,
                            given_name,
                            family_name,
                            active,
                            raw_payload,
                        ),
                    )
            except _DB_ERRORS as exc:
                logger.error(f"Error saving SCIM user in DB: {exc}")
    _in_memory_db["scim_users"][scim_id] = user_data


async def db_get_scim_user(scim_id: str) -> dict[str, Any] | None:
    async with get_tenant_conn() as conn:
        if conn:
            try:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT raw_payload FROM scim_users WHERE scim_id = %s;",
                        (scim_id,),
                    )
                    row = await cur.fetchone()
                    if row:
                        return json.loads(row[0]) if isinstance(row[0], str) else row[0]
            except _DB_ERRORS as exc:
                logger.error(f"Error fetching SCIM user from DB: {exc}")
    return _in_memory_db["scim_users"].get(scim_id)


async def db_delete_scim_user(scim_id: str) -> bool:
    async with get_tenant_conn() as conn:
        if conn:
            try:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "DELETE FROM scim_users WHERE scim_id = %s;", (scim_id,)
                    )
            except _DB_ERRORS as exc:
                logger.error(f"Error deleting SCIM user from DB: {exc}")
    if scim_id in _in_memory_db["scim_users"]:
        del _in_memory_db["scim_users"][scim_id]
        return True
    return False


async def db_list_scim_users() -> list[dict[str, Any]]:
    users = []
    async with get_tenant_conn() as conn:
        if conn:
            try:
                async with conn.cursor() as cur:
                    await cur.execute("SELECT raw_payload FROM scim_users;")
                    rows = await cur.fetchall()
                    for row in rows:
                        users.append(
                            json.loads(row[0]) if isinstance(row[0], str) else row[0]
                        )
                    return users
            except _DB_ERRORS as exc:
                logger.error(f"Error listing SCIM users from DB: {exc}")
    return list(_in_memory_db["scim_users"].values())


# --- Outbox Relay Functions ---
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
