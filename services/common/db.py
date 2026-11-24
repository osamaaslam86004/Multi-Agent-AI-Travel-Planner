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
from datetime import UTC, datetime
from typing import Any

try:
    import psycopg
    from psycopg_pool import AsyncConnectionPool

    _PSYCOPG_ERRORS = (psycopg.Error,)
except ImportError:
    psycopg = None
    AsyncConnectionPool = None
    _PSYCOPG_ERRORS = ()
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
    "user_credentials": {},
    "federated_identities": [],
    "login_history": [],
    "orgs": {},
    "org_memberships": [],
    "role_assignments": [],
    "idp_configs": {},
    "scim_tokens": {},
    "scim_groups": {},
    "scim_users": {},
    "delegated_permissions": {},
    "trip_shares": {},
    "active_sessions": {},
    "org_invitations": {},
}


async def init_identity_schema(conn: Any) -> None:
    """Initializing Phase 2 Identity tables if not present."""
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
        deletion_requested_at TIMESTAMPTZ,
        deletion_scheduled_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS user_credentials (
        user_id VARCHAR(64) PRIMARY KEY REFERENCES user_profiles(user_id) ON DELETE CASCADE,
        password_hash TEXT NOT NULL,
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
    CREATE TABLE IF NOT EXISTS org_invitations (
        token VARCHAR(128) PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        org_id VARCHAR(64) NOT NULL REFERENCES orgs(org_id) ON DELETE CASCADE,
        role VARCHAR(64) NOT NULL DEFAULT 'member',
        created_by VARCHAR(64) NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL,
        accepted BOOLEAN DEFAULT FALSE
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
        org_id VARCHAR(64) REFERENCES orgs(org_id) ON DELETE CASCADE,
        user_name VARCHAR(255) NOT NULL UNIQUE,
        given_name VARCHAR(255),
        family_name VARCHAR(255),
        active BOOLEAN DEFAULT TRUE,
        raw_payload JSONB NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS trips (
        trip_id VARCHAR(64) PRIMARY KEY,
        tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
        user_id VARCHAR(64) NOT NULL,
        correlation_id VARCHAR(64) UNIQUE NOT NULL,
        user_query TEXT NOT NULL,
        flight_results TEXT,
        hotel_results TEXT,
        weather_results TEXT,
        itinerary TEXT,
        final_response TEXT,
        flight_degraded BOOLEAN DEFAULT FALSE,
        hotel_degraded BOOLEAN DEFAULT FALSE,
        weather_degraded BOOLEAN DEFAULT FALSE,
        status VARCHAR(32) NOT NULL DEFAULT 'GATHERING',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS trip_events (
        id VARCHAR(64) PRIMARY KEY,
        tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
        correlation_id VARCHAR(64) NOT NULL,
        event_type VARCHAR(128) NOT NULL,
        payload JSONB NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS llm_usage (
        id VARCHAR(64) PRIMARY KEY,
        tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
        user_id VARCHAR(64) NOT NULL,
        correlation_id VARCHAR(64) NOT NULL,
        provider VARCHAR(64) NOT NULL,
        model VARCHAR(64) NOT NULL,
        prompt_tokens INT NOT NULL,
        completion_tokens INT NOT NULL,
        total_tokens INT NOT NULL,
        latency_ms REAL NOT NULL,
        cost_estimate REAL DEFAULT 0.0,
        created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS outbox (
        id SERIAL PRIMARY KEY,
        tenant_id VARCHAR(64) NOT NULL DEFAULT 'default',
        correlation_id VARCHAR(64) NOT NULL,
        stream_name VARCHAR(128) NOT NULL,
        event_type VARCHAR(128) NOT NULL,
        payload JSONB NOT NULL,
        processed BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        processed_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS delegated_permissions (
        id VARCHAR(64) PRIMARY KEY,
        grantor_user_id VARCHAR(64) NOT NULL REFERENCES user_profiles(user_id) ON DELETE CASCADE,
        delegate_user_id VARCHAR(64) NOT NULL REFERENCES user_profiles(user_id) ON DELETE CASCADE,
        resource_type VARCHAR(64) NOT NULL,
        resource_id VARCHAR(64) NOT NULL,
        permissions JSONB NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS trip_shares (
        id VARCHAR(64) PRIMARY KEY,
        trip_id VARCHAR(64) NOT NULL,
        owner_id VARCHAR(64) NOT NULL REFERENCES user_profiles(user_id) ON DELETE CASCADE,
        grantee_id VARCHAR(64) NOT NULL REFERENCES user_profiles(user_id) ON DELETE CASCADE,
        permission_level VARCHAR(32) NOT NULL DEFAULT 'read',
        expires_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(trip_id, grantee_id)
    );
    CREATE TABLE IF NOT EXISTS active_sessions (
        session_id VARCHAR(64) PRIMARY KEY,
        user_id VARCHAR(64) NOT NULL REFERENCES user_profiles(user_id) ON DELETE CASCADE,
        ip_address VARCHAR(45) NOT NULL,
        user_agent TEXT NOT NULL,
        device_fingerprint VARCHAR(64),
        is_trusted BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        last_active_at TIMESTAMPTZ DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS user_mfa_factors (
        user_id VARCHAR(64) PRIMARY KEY REFERENCES user_profiles(user_id) ON DELETE CASCADE,
        secret_encrypted TEXT NOT NULL,
        backup_codes_encrypted TEXT NOT NULL,
        mfa_type VARCHAR(32) NOT NULL DEFAULT 'totp',
        enabled BOOLEAN DEFAULT FALSE,
        updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS verified_domains (
        domain VARCHAR(255) PRIMARY KEY,
        org_id VARCHAR(64) NOT NULL REFERENCES orgs(org_id) ON DELETE CASCADE,
        verification_token VARCHAR(128) NOT NULL,
        verified BOOLEAN DEFAULT FALSE,
        verified_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS deletion_cancellation_tokens (
        token_hash VARCHAR(128) PRIMARY KEY,
        user_id VARCHAR(64) NOT NULL REFERENCES user_profiles(user_id) ON DELETE CASCADE,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_user_profiles_lower_email ON user_profiles (LOWER(email));
    CREATE INDEX IF NOT EXISTS idx_login_history_user_ts ON login_history (user_id, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_federated_identities_user ON federated_identities (user_id);
    CREATE INDEX IF NOT EXISTS idx_org_invitations_email ON org_invitations (LOWER(email));
    CREATE INDEX IF NOT EXISTS idx_scim_users_org ON scim_users (org_id);
    CREATE INDEX IF NOT EXISTS idx_role_assignments_user ON role_assignments (user_id);

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
        if get_settings().app.environment.lower() in ("production", "staging"):
            raise RuntimeError(
                "PostgreSQL driver unavailable; identity persistence cannot fall back to memory in production/staging."
            )
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
        environment = get_settings().app.environment.lower()
        if environment in ("production", "staging"):
            logger.exception(
                "PostgreSQL initialization failed; refusing ephemeral identity persistence in %s",
                environment,
            )
            _pool = None
            raise RuntimeError(
                "PostgreSQL unavailable; fail-closed identity persistence required."
            ) from exc
        logger.warning(
            "Postgres pool initialization unavailable: %s. Development-only memory fallback enabled.",
            exc,
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
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SET LOCAL app.current_tenant_id = %s;", (tenant_id,))
        yield conn


# --- User Profile & Credential Repository ---
async def db_get_user_by_email(
    email: str, tenant_id: str | None = None
) -> dict[str, Any] | None:
    email_clean = email.lower().strip()
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn(tenant_id or "default") as conn:
            if conn:
                async with conn.cursor() as cur:
                    if tenant_id:
                        await cur.execute(
                            "SELECT user_id, tenant_id, org_id, email, display_name, avatar_url, bio, timezone, "
                            "preferred_currency, status, roles, email_verified, mfa_enabled, deletion_requested_at, deletion_scheduled_at, created_at, updated_at "
                            "FROM user_profiles WHERE LOWER(email) = %s AND (tenant_id = %s OR tenant_id = 'default');",
                            (email_clean, tenant_id),
                        )
                    else:
                        await cur.execute(
                            "SELECT user_id, tenant_id, org_id, email, display_name, avatar_url, bio, timezone, "
                            "preferred_currency, status, roles, email_verified, mfa_enabled, deletion_requested_at, deletion_scheduled_at, created_at, updated_at "
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
                            "deletion_requested_at": str(row[13]) if row[13] else None,
                            "deletion_scheduled_at": str(row[14]) if row[14] else None,
                            "created_at": str(row[15]),
                            "updated_at": str(row[16]),
                        }
                    return None
    for u in _in_memory_db["user_profiles"].values():
        if u.get("email", "").lower() == email_clean:
            if tenant_id and u.get("tenant_id") not in (tenant_id, "default"):
                continue
            return u
    return None


async def db_get_user_by_id(
    user_id: str, tenant_id: str | None = None
) -> dict[str, Any] | None:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn(tenant_id or "default") as conn:
            if conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT user_id, tenant_id, org_id, email, display_name, avatar_url, bio, timezone, "
                        "preferred_currency, status, roles, email_verified, mfa_enabled, deletion_requested_at, deletion_scheduled_at, created_at, updated_at "
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
                            "deletion_requested_at": str(row[13]) if row[13] else None,
                            "deletion_scheduled_at": str(row[14]) if row[14] else None,
                            "created_at": str(row[15]),
                            "updated_at": str(row[16]),
                        }
                    return None
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
    del_req = user_dict.get("deletion_requested_at")
    del_sched = user_dict.get("deletion_scheduled_at")
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn(tenant_id) as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO user_profiles (user_id, tenant_id, org_id, email, display_name, avatar_url, bio, timezone, preferred_currency, status, roles, email_verified, mfa_enabled, deletion_requested_at, deletion_scheduled_at) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s) "
                        "ON CONFLICT (user_id) DO UPDATE SET "
                        "display_name = EXCLUDED.display_name, avatar_url = EXCLUDED.avatar_url, bio = EXCLUDED.bio, "
                        "timezone = EXCLUDED.timezone, preferred_currency = EXCLUDED.preferred_currency, status = EXCLUDED.status, "
                        "roles = EXCLUDED.roles, email_verified = EXCLUDED.email_verified, mfa_enabled = EXCLUDED.mfa_enabled, "
                        "org_id = COALESCE(EXCLUDED.org_id, user_profiles.org_id), tenant_id = EXCLUDED.tenant_id, deletion_requested_at = COALESCE(EXCLUDED.deletion_requested_at, user_profiles.deletion_requested_at), deletion_scheduled_at = COALESCE(EXCLUDED.deletion_scheduled_at, user_profiles.deletion_scheduled_at), "
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
                            del_req,
                            del_sched,
                        ),
                    )
                return
    _in_memory_db["user_profiles"][user_id] = user_dict


async def db_save_user_password(user_id: str, password_hash: str) -> None:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO user_credentials (user_id, password_hash) VALUES (%s, %s) "
                        "ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = NOW();",
                        (user_id, password_hash),
                    )
                return
    _in_memory_db["user_credentials"][user_id] = password_hash


async def db_get_user_password(user_id: str) -> str | None:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT password_hash FROM user_credentials WHERE user_id = %s;",
                        (user_id,),
                    )
                    row = await cur.fetchone()
                    if row:
                        return row[0]
                    return None
    return _in_memory_db["user_credentials"].get(user_id)


# --- Federated Identities Repository ---
async def db_link_federated_identity(
    user_id: str,
    provider: str,
    issuer: str,
    sub: str,
    email: str | None = None,
    email_verified: bool = False,
) -> str:
    fed_id = f"fed_{uuid.uuid4().hex[:12]}"
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO federated_identities (id, user_id, provider, issuer, sub, email, email_verified) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s) "
                        "ON CONFLICT (provider, issuer, sub) DO UPDATE SET email = EXCLUDED.email, email_verified = EXCLUDED.email_verified;",
                        (fed_id, user_id, provider, issuer, sub, email, email_verified),
                    )
                return fed_id
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


async def db_unlink_federated_identity(user_id: str, provider: str) -> int:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "DELETE FROM federated_identities WHERE user_id = %s AND provider = %s;",
                        (user_id, provider),
                    )
                    return cur.rowcount
    before = len(_in_memory_db["federated_identities"])
    _in_memory_db["federated_identities"] = [
        f
        for f in _in_memory_db["federated_identities"]
        if not (f.get("user_id") == user_id and f.get("provider") == provider)
    ]
    return before - len(_in_memory_db["federated_identities"])


async def db_get_federated_identity(
    provider: str, issuer: str, sub: str
) -> dict[str, Any] | None:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
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
                    return None
    for fi in _in_memory_db["federated_identities"]:
        if fi["provider"] == provider and fi["issuer"] == issuer and fi["sub"] == sub:
            return fi
    return None


async def db_get_user_linked_providers(user_id: str) -> list[dict[str, Any]]:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT provider, sub, email, created_at FROM federated_identities WHERE user_id = %s;",
                        (user_id,),
                    )
                    rows = await cur.fetchall()
                    return [
                        {
                            "provider": r[0],
                            "provider_user_id": r[1],
                            "email": r[2],
                            "linked_at": str(r[3]),
                        }
                        for r in rows
                    ]
    return [
        {
            "provider": f["provider"],
            "provider_user_id": f["sub"],
            "email": f.get("email"),
            "linked_at": f.get("created_at", datetime.now(UTC).isoformat()),
        }
        for f in _in_memory_db["federated_identities"]
        if f.get("user_id") == user_id
    ]


# --- Multi-Org & Role Assignments Repository ---
async def db_assign_role(
    user_id: str, role: str, scope_type: str, scope_id: str | None, assigned_by: str
) -> str:
    assignment_id = f"role_{uuid.uuid4().hex[:16]}"
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO role_assignments (id, user_id, role, scope_type, scope_id, assigned_by) VALUES (%s,%s,%s,%s,%s,%s);",
                        (
                            assignment_id,
                            user_id,
                            role,
                            scope_type,
                            scope_id,
                            assigned_by,
                        ),
                    )
                return assignment_id
    _in_memory_db["role_assignments"].append(
        {
            "id": assignment_id,
            "user_id": user_id,
            "role": role,
            "scope_type": scope_type,
            "scope_id": scope_id,
            "assigned_by": assigned_by,
        }
    )
    return assignment_id


async def db_revoke_role(
    user_id: str, role: str, scope_type: str, scope_id: str | None
) -> int:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "DELETE FROM role_assignments WHERE user_id=%s AND role=%s AND scope_type=%s AND scope_id IS NOT DISTINCT FROM %s;",
                        (user_id, role, scope_type, scope_id),
                    )
                    return cur.rowcount
    before = len(_in_memory_db["role_assignments"])
    _in_memory_db["role_assignments"] = [
        a
        for a in _in_memory_db["role_assignments"]
        if not (
            a.get("user_id") == user_id
            and a.get("role") == role
            and a.get("scope_type") == scope_type
            and a.get("scope_id") == scope_id
        )
    ]
    return before - len(_in_memory_db["role_assignments"])


async def db_get_user_org_memberships(user_id: str) -> list[dict[str, Any]]:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT org_id, role, created_at FROM org_memberships WHERE user_id = %s;",
                        (user_id,),
                    )
                    rows = await cur.fetchall()
                    return [
                        {"org_id": r[0], "role": r[1], "created_at": str(r[2])}
                        for r in rows
                    ]
    return [m for m in _in_memory_db["org_memberships"] if m.get("user_id") == user_id]


async def db_add_org_membership(
    user_id: str, org_id: str, role: str = "member"
) -> None:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO org_memberships (user_id, org_id, role) VALUES (%s, %s, %s) "
                        "ON CONFLICT (user_id, org_id) DO UPDATE SET role = EXCLUDED.role;",
                        (user_id, org_id, role),
                    )
                return
    for m in _in_memory_db["org_memberships"]:
        if m.get("user_id") == user_id and m.get("org_id") == org_id:
            m["role"] = role
            return
    _in_memory_db["org_memberships"].append(
        {
            "user_id": user_id,
            "org_id": org_id,
            "role": role,
            "created_at": datetime.now(UTC).isoformat(),
        }
    )


async def db_remove_org_membership(user_id: str, org_id: str) -> None:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "DELETE FROM org_memberships WHERE user_id = %s AND org_id = %s;",
                        (user_id, org_id),
                    )
                return
    _in_memory_db["org_memberships"] = [
        m
        for m in _in_memory_db["org_memberships"]
        if not (m.get("user_id") == user_id and m.get("org_id") == org_id)
    ]


# --- Invitations Repository ---
async def db_save_invitation(
    token: str, email: str, org_id: str, role: str, created_by: str, expires_at: str
) -> None:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO org_invitations (token, email, org_id, role, created_by, expires_at) "
                        "VALUES (%s, %s, %s, %s, %s, %s);",
                        (
                            token,
                            email.lower().strip(),
                            org_id,
                            role,
                            created_by,
                            expires_at,
                        ),
                    )
                return
    _in_memory_db["org_invitations"][token] = {
        "token": token,
        "email": email.lower().strip(),
        "org_id": org_id,
        "role": role,
        "created_by": created_by,
        "expires_at": expires_at,
        "accepted": False,
    }


async def db_get_invitation(token: str) -> dict[str, Any] | None:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT token, email, org_id, role, created_by, expires_at, accepted "
                        "FROM org_invitations WHERE token = %s;",
                        (token,),
                    )
                    row = await cur.fetchone()
                    if row:
                        return {
                            "token": row[0],
                            "email": row[1],
                            "org_id": row[2],
                            "role": row[3],
                            "created_by": row[4],
                            "expires_at": str(row[5]),
                            "accepted": row[6],
                        }
                    return None
    return _in_memory_db["org_invitations"].get(token)


async def db_accept_invitation(token: str) -> None:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "UPDATE org_invitations SET accepted = TRUE WHERE token = %s;",
                        (token,),
                    )
                return
    if token in _in_memory_db["org_invitations"]:
        _in_memory_db["org_invitations"][token]["accepted"] = True


# --- SCIM Tokens Repository ---
async def db_save_scim_token(org_id: str, token_hash: str) -> str:
    token_id = f"scim_tok_{uuid.uuid4().hex[:12]}"
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO scim_tokens (token_id, org_id, token_hash) VALUES (%s, %s, %s);",
                        (token_id, org_id, token_hash),
                    )
                return token_id
    _in_memory_db["scim_tokens"][token_id] = {
        "token_id": token_id,
        "org_id": org_id,
        "token_hash": token_hash,
    }
    return token_id


async def db_get_scim_token_by_hash(token_hash: str) -> dict[str, Any] | None:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
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
                    return None
    for tok in _in_memory_db["scim_tokens"].values():
        if tok["token_hash"] == token_hash:
            return tok
    return None


# --- IdP Config Repository ---
async def db_get_idp_config(org_id: str) -> dict[str, Any] | None:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT org_id, idp_name, sso_type, issuer_url, client_id, enforce_sso, allowed_domains, group_role_mappings, metadata_xml, client_secret "
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
                            "client_secret": row[9],
                        }
                    return None
    return _in_memory_db["idp_configs"].get(org_id)


async def db_save_idp_config(cfg_dict: dict[str, Any]) -> None:
    org_id = cfg_dict["org_id"]
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
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
                        "INSERT INTO idp_configs (org_id, idp_name, sso_type, issuer_url, client_id, client_secret, enforce_sso, allowed_domains, group_role_mappings, metadata_xml) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s) "
                        "ON CONFLICT (org_id) DO UPDATE SET idp_name = EXCLUDED.idp_name, sso_type = EXCLUDED.sso_type, "
                        "issuer_url = EXCLUDED.issuer_url, client_id = EXCLUDED.client_id, client_secret = EXCLUDED.client_secret, "
                        "enforce_sso = EXCLUDED.enforce_sso, allowed_domains = EXCLUDED.allowed_domains, "
                        "group_role_mappings = EXCLUDED.group_role_mappings, metadata_xml = EXCLUDED.metadata_xml, updated_at = NOW();",
                        (
                            org_id,
                            cfg_dict["idp_name"],
                            cfg_dict["sso_type"],
                            cfg_dict["issuer_url"],
                            cfg_dict["client_id"],
                            cfg_dict.get("client_secret"),
                            cfg_dict.get("enforce_sso", False),
                            json.dumps(cfg_dict.get("allowed_domains", [])),
                            json.dumps(cfg_dict.get("group_role_mappings", {})),
                            cfg_dict.get("metadata_xml"),
                        ),
                    )
                return
    _in_memory_db["idp_configs"][org_id] = cfg_dict


async def db_list_all_idp_configs() -> list[dict[str, Any]]:
    configs = []
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT org_id, idp_name, sso_type, issuer_url, client_id, enforce_sso, allowed_domains, group_role_mappings, metadata_xml, client_secret FROM idp_configs;"
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
                                "client_secret": row[9],
                            }
                        )
                    return configs
    return list(_in_memory_db["idp_configs"].values())


# --- SCIM Users & Groups Repository ---
async def db_save_scim_user(
    user_data: dict[str, Any], org_id: str | None = None
) -> None:
    scim_id = user_data["id"]
    user_name = user_data["userName"]
    name_obj = user_data.get("name") or {}
    given_name = name_obj.get("givenName") if isinstance(name_obj, dict) else None
    family_name = name_obj.get("familyName") if isinstance(name_obj, dict) else None
    active = user_data.get("active", True)
    raw_payload = json.dumps(user_data)
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO scim_users (scim_id, org_id, user_name, given_name, family_name, active, raw_payload) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb) "
                        "ON CONFLICT (scim_id) DO UPDATE SET user_name = EXCLUDED.user_name, given_name = EXCLUDED.given_name, "
                        "family_name = EXCLUDED.family_name, active = EXCLUDED.active, raw_payload = EXCLUDED.raw_payload, updated_at = NOW();",
                        (
                            scim_id,
                            org_id,
                            user_name,
                            given_name,
                            family_name,
                            active,
                            raw_payload,
                        ),
                    )
                return
    _in_memory_db["scim_users"][scim_id] = user_data


async def db_get_scim_user(
    scim_id: str, org_id: str | None = None
) -> dict[str, Any] | None:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.cursor() as cur:
                    if org_id:
                        await cur.execute(
                            "SELECT raw_payload FROM scim_users WHERE scim_id = %s AND (org_id = %s OR org_id IS NULL);",
                            (scim_id, org_id),
                        )
                    else:
                        await cur.execute(
                            "SELECT raw_payload FROM scim_users WHERE scim_id = %s;",
                            (scim_id,),
                        )
                    row = await cur.fetchone()
                    if row:
                        return json.loads(row[0]) if isinstance(row[0], str) else row[0]
                    return None
    return _in_memory_db["scim_users"].get(scim_id)


async def db_delete_scim_user(scim_id: str, org_id: str | None = None) -> bool:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    if org_id:
                        await cur.execute(
                            "DELETE FROM scim_users WHERE scim_id = %s AND (org_id = %s OR org_id IS NULL);",
                            (scim_id, org_id),
                        )
                    else:
                        await cur.execute(
                            "DELETE FROM scim_users WHERE scim_id = %s;", (scim_id,)
                        )
                return True
    if scim_id in _in_memory_db["scim_users"]:
        del _in_memory_db["scim_users"][scim_id]
        return True
    return False


async def db_list_scim_users(org_id: str | None = None) -> list[dict[str, Any]]:
    users = []
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.cursor() as cur:
                    if org_id:
                        await cur.execute(
                            "SELECT raw_payload FROM scim_users WHERE org_id = %s OR org_id IS NULL;",
                            (org_id,),
                        )
                    else:
                        await cur.execute("SELECT raw_payload FROM scim_users;")
                    rows = await cur.fetchall()
                    for row in rows:
                        users.append(
                            json.loads(row[0]) if isinstance(row[0], str) else row[0]
                        )
                    return users
    return list(_in_memory_db["scim_users"].values())


async def db_save_scim_group(
    group_data: dict[str, Any], org_id: str | None = None
) -> None:
    grp_id = group_data["id"]
    display_name = group_data.get("displayName", "")
    members = json.dumps(group_data.get("members", []))
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO scim_groups (group_id, org_id, display_name, members) VALUES (%s, %s, %s, %s::jsonb) "
                        "ON CONFLICT (group_id) DO UPDATE SET display_name = EXCLUDED.display_name, members = EXCLUDED.members;",
                        (grp_id, org_id, display_name, members),
                    )
                return
    _in_memory_db["scim_groups"][grp_id] = group_data


async def db_get_scim_group(
    group_id: str, org_id: str | None = None
) -> dict[str, Any] | None:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.cursor() as cur:
                    if org_id:
                        await cur.execute(
                            "SELECT group_id, display_name, members FROM scim_groups WHERE group_id = %s AND (org_id = %s OR org_id IS NULL);",
                            (group_id, org_id),
                        )
                    else:
                        await cur.execute(
                            "SELECT group_id, display_name, members FROM scim_groups WHERE group_id = %s;",
                            (group_id,),
                        )
                    row = await cur.fetchone()
                    if row:
                        return {
                            "id": row[0],
                            "displayName": row[1],
                            "members": json.loads(row[2])
                            if isinstance(row[2], str)
                            else row[2],
                        }
                    return None
    return _in_memory_db["scim_groups"].get(group_id)


async def db_delete_scim_group(group_id: str, org_id: str | None = None) -> bool:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    if org_id:
                        await cur.execute(
                            "DELETE FROM scim_groups WHERE group_id = %s AND (org_id = %s OR org_id IS NULL);",
                            (group_id, org_id),
                        )
                    else:
                        await cur.execute(
                            "DELETE FROM scim_groups WHERE group_id = %s;", (group_id,)
                        )
                return True
    if group_id in _in_memory_db["scim_groups"]:
        del _in_memory_db["scim_groups"][group_id]
        return True
    return False


async def db_list_scim_groups(org_id: str | None = None) -> list[dict[str, Any]]:
    groups = []
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.cursor() as cur:
                    if org_id:
                        await cur.execute(
                            "SELECT group_id, display_name, members FROM scim_groups WHERE org_id = %s OR org_id IS NULL;",
                            (org_id,),
                        )
                    else:
                        await cur.execute(
                            "SELECT group_id, display_name, members FROM scim_groups;"
                        )
                    rows = await cur.fetchall()
                    for row in rows:
                        groups.append(
                            {
                                "id": row[0],
                                "displayName": row[1],
                                "members": json.loads(row[2])
                                if isinstance(row[2], str)
                                else row[2],
                            }
                        )
                    return groups
    return list(_in_memory_db["scim_groups"].values())


# --- Delegated Permissions & Trip Sharing Repository ---
async def db_save_delegated_permission(delegation_dict: dict[str, Any]) -> str:
    del_id = delegation_dict.get("id") or f"del_{uuid.uuid4().hex[:12]}"
    delegation_dict["id"] = del_id
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO delegated_permissions (id, grantor_user_id, delegate_user_id, resource_type, resource_id, permissions, expires_at) "
                        "VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s);",
                        (
                            del_id,
                            delegation_dict["grantor_user_id"],
                            delegation_dict["delegate_user_id"],
                            delegation_dict["resource_type"],
                            delegation_dict["resource_id"],
                            json.dumps(delegation_dict["permissions"]),
                            delegation_dict["expires_at"],
                        ),
                    )
                return del_id
    _in_memory_db["delegated_permissions"][del_id] = delegation_dict
    return del_id


async def db_save_trip_share(share_dict: dict[str, Any]) -> str:
    share_id = share_dict.get("id") or f"share_{uuid.uuid4().hex[:12]}"
    share_dict["id"] = share_id
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO trip_shares (id, trip_id, owner_id, grantee_id, permission_level, expires_at) "
                        "VALUES (%s, %s, %s, %s, %s, %s) "
                        "ON CONFLICT (trip_id, grantee_id) DO UPDATE SET permission_level = EXCLUDED.permission_level, expires_at = EXCLUDED.expires_at;",
                        (
                            share_id,
                            share_dict["trip_id"],
                            share_dict["owner_id"],
                            share_dict["grantee_id"],
                            share_dict.get("permission_level", "read"),
                            share_dict.get("expires_at"),
                        ),
                    )
                return share_id
    _in_memory_db["trip_shares"][share_id] = share_dict
    return share_id


# --- Trips & Usage Repository ---
async def upsert_trip_result(
    tenant_id: str,
    user_id: str,
    correlation_id: str,
    user_query: str,
    flight_results: str = "",
    hotel_results: str = "",
    weather_results: str = "",
    itinerary: str = "",
    final_response: str = "",
    flight_degraded: bool = False,
    hotel_degraded: bool = False,
    weather_degraded: bool = False,
    status: str = "DONE",
) -> None:
    trip_id = f"trip_{correlation_id}"
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn(tenant_id) as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO trips (trip_id, tenant_id, user_id, correlation_id, user_query, flight_results, "
                        "hotel_results, weather_results, itinerary, final_response, flight_degraded, hotel_degraded, "
                        "weather_degraded, status) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
                        "ON CONFLICT (correlation_id) DO UPDATE SET "
                        "flight_results = EXCLUDED.flight_results, hotel_results = EXCLUDED.hotel_results, "
                        "weather_results = EXCLUDED.weather_results, itinerary = EXCLUDED.itinerary, "
                        "final_response = EXCLUDED.final_response, flight_degraded = EXCLUDED.flight_degraded, "
                        "hotel_degraded = EXCLUDED.hotel_degraded, weather_degraded = EXCLUDED.weather_degraded, "
                        "status = EXCLUDED.status, updated_at = NOW();",
                        (
                            trip_id,
                            tenant_id,
                            user_id,
                            correlation_id,
                            user_query,
                            flight_results,
                            hotel_results,
                            weather_results,
                            itinerary,
                            final_response,
                            flight_degraded,
                            hotel_degraded,
                            weather_degraded,
                            status,
                        ),
                    )
                return
    _in_memory_db["trips"][correlation_id] = {
        "trip_id": trip_id,
        "tenant_id": tenant_id,
        "user_id": user_id,
        "correlation_id": correlation_id,
        "user_query": user_query,
        "flight_results": flight_results,
        "hotel_results": hotel_results,
        "weather_results": weather_results,
        "itinerary": itinerary,
        "final_response": final_response,
        "flight_degraded": flight_degraded,
        "hotel_degraded": hotel_degraded,
        "weather_degraded": weather_degraded,
        "status": status,
    }


async def db_can_access_trip(
    user_id: str, trip_id: str, tenant_id: str, action: str = "read"
) -> bool:
    trip = await get_trip_by_id(trip_id, tenant_id=tenant_id)
    if not trip:
        return False
    if trip.get("tenant_id") != tenant_id and tenant_id != "default":
        return False
    if trip.get("user_id") == user_id:
        return True
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn(tenant_id) as conn:
            if conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT permission_level FROM trip_shares WHERE trip_id=%s AND grantee_id=%s AND (expires_at IS NULL OR expires_at > NOW());",
                        (trip_id, user_id),
                    )
                    share = await cur.fetchone()
                    allowed_levels = {
                        "read": {"read", "write", "admin"},
                        "write": {"write", "admin"},
                        "share": {"admin"},
                        "delete": {"admin"},
                    }
                    if share and share[0] in allowed_levels.get(action, set()):
                        return True
                    await cur.execute(
                        "SELECT permissions FROM delegated_permissions WHERE delegate_user_id=%s AND resource_type='trip' AND resource_id=%s AND expires_at > NOW();",
                        (user_id, trip_id),
                    )
                    for row in await cur.fetchall():
                        permissions = (
                            row[0] if isinstance(row[0], list) else json.loads(row[0])
                        )
                        if (
                            action in permissions
                            or (action == "read" and "write" in permissions)
                            or "manage" in permissions
                        ):
                            return True
                return False
    for share in _in_memory_db["trip_shares"].values():
        if share.get("trip_id") == trip_id and share.get("grantee_id") == user_id:
            expiry = share.get("expires_at")
            if not expiry or str(expiry) > datetime.now(UTC).isoformat():
                level = share.get("permission_level", "read")
                if level in {"admin", "write", "read"} and action == "read":
                    return True
                if level in {"admin", "write"} and action == "write":
                    return True
                if level == "admin" and action in ("share", "delete"):
                    return True
    for delegation in _in_memory_db["delegated_permissions"].values():
        if (
            delegation.get("resource_type") == "trip"
            and delegation.get("resource_id") == trip_id
            and delegation.get("delegate_user_id") == user_id
        ):
            expiry = delegation.get("expires_at")
            try:
                expires_at = (
                    datetime.fromisoformat(str(expiry))
                    if expiry
                    else None
                )
            except ValueError:
                expires_at = None
            if expires_at and expires_at > datetime.now(UTC):
                permissions = delegation.get("permissions", [])
                if (
                    action in permissions
                    or (action == "read" and "write" in permissions)
                    or "manage" in permissions
                ):
                    return True
    return False


async def get_trip_by_id(
    correlation_id: str, tenant_id: str = "default"
) -> dict[str, Any] | None:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn(tenant_id) as conn:
            if conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT trip_id, tenant_id, user_id, correlation_id, user_query, flight_results, "
                        "hotel_results, weather_results, itinerary, final_response, flight_degraded, hotel_degraded, "
                        "weather_degraded, status, created_at, updated_at "
                        "FROM trips WHERE (correlation_id = %s OR trip_id = %s) AND (tenant_id = %s OR tenant_id = 'default');",
                        (correlation_id, correlation_id, tenant_id),
                    )
                    row = await cur.fetchone()
                    if row:
                        return {
                            "trip_id": row[0],
                            "tenant_id": row[1],
                            "user_id": row[2],
                            "correlation_id": row[3],
                            "user_query": row[4],
                            "flight_results": row[5],
                            "hotel_results": row[6],
                            "weather_results": row[7],
                            "itinerary": row[8],
                            "final_response": row[9],
                            "flight_degraded": row[10],
                            "hotel_degraded": row[11],
                            "weather_degraded": row[12],
                            "status": row[13],
                            "created_at": str(row[14]),
                            "updated_at": str(row[15]),
                        }
                    return None
    trip = _in_memory_db["trips"].get(correlation_id)
    if not trip:
        for t in _in_memory_db["trips"].values():
            if t.get("trip_id") == correlation_id:
                trip = t
                break
    if trip and (trip.get("tenant_id") == tenant_id or tenant_id == "default"):
        return trip
    return None


async def db_list_user_trips(
    user_id: str, tenant_id: str = "default"
) -> list[dict[str, Any]]:
    trips = []
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn(tenant_id) as conn:
            if conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT trip_id, tenant_id, user_id, correlation_id, user_query, status, created_at "
                        "FROM trips WHERE (user_id = %s OR trip_id IN (SELECT trip_id FROM trip_shares WHERE grantee_id = %s)) "
                        "AND (tenant_id = %s OR tenant_id = 'default') ORDER BY created_at DESC;",
                        (user_id, user_id, tenant_id),
                    )
                    rows = await cur.fetchall()
                    for r in rows:
                        trips.append(
                            {
                                "trip_id": r[0],
                                "tenant_id": r[1],
                                "user_id": r[2],
                                "correlation_id": r[3],
                                "user_query": r[4],
                                "status": r[5],
                                "created_at": str(r[6]),
                            }
                        )
                    return trips
    for t in _in_memory_db["trips"].values():
        if (
            t.get("user_id") == user_id
            or db_can_access_trip_sync_memory(user_id, t.get("trip_id"))
        ) and (t.get("tenant_id") in (tenant_id, "default")):
            trips.append(t)
    return trips


def db_can_access_trip_sync_memory(user_id: str, trip_id: str) -> bool:
    for s in _in_memory_db["trip_shares"].values():
        if s.get("trip_id") == trip_id and s.get("grantee_id") == user_id:
            return True
    return False


async def record_trip_event(
    tenant_id: str,
    correlation_id: str,
    event_type: str,
    payload: dict[str, Any],
) -> str:
    evt_id = f"evt_{uuid.uuid4().hex[:12]}"
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn(tenant_id) as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO trip_events (id, tenant_id, correlation_id, event_type, payload) "
                        "VALUES (%s, %s, %s, %s, %s::jsonb);",
                        (
                            evt_id,
                            tenant_id,
                            correlation_id,
                            event_type,
                            json.dumps(payload),
                        ),
                    )
                return evt_id
    _in_memory_db["trip_events"].append(
        {
            "id": evt_id,
            "tenant_id": tenant_id,
            "correlation_id": correlation_id,
            "event_type": event_type,
            "payload": payload,
        }
    )
    return evt_id


def calculate_cost(
    provider_name: str, model_name: str, prompt_tokens: int, completion_tokens: int
) -> float:
    p_lower = provider_name.lower()
    if "groq" in p_lower:
        return (prompt_tokens * 0.59 / 1_000_000.0) + (
            completion_tokens * 0.79 / 1_000_000.0
        )
    elif "gemini" in p_lower:
        return (prompt_tokens * 0.15 / 1_000_000.0) + (
            completion_tokens * 0.60 / 1_000_000.0
        )
    return 0.0


async def record_llm_usage(
    tenant_id: str,
    user_id: str,
    correlation_id: str,
    provider: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
    latency_ms: float,
    cost_estimate: float | None = None,
) -> str:
    usage_id = f"usg_{uuid.uuid4().hex[:12]}"
    cost = (
        cost_estimate
        if cost_estimate is not None
        else calculate_cost(provider, model, prompt_tokens, completion_tokens)
    )
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn(tenant_id) as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO llm_usage (id, tenant_id, user_id, correlation_id, provider, model, prompt_tokens, completion_tokens, total_tokens, latency_ms, cost_estimate) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);",
                        (
                            usage_id,
                            tenant_id,
                            user_id,
                            correlation_id,
                            provider,
                            model,
                            prompt_tokens,
                            completion_tokens,
                            total_tokens,
                            latency_ms,
                            cost,
                        ),
                    )
                return usage_id
    _in_memory_db["llm_usage"].append(
        {
            "id": usage_id,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "correlation_id": correlation_id,
            "provider": provider,
            "model": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "latency_ms": latency_ms,
            "cost_estimate": cost,
        }
    )
    return usage_id


# --- Outbox Relay Functions ---
async def write_outbox(
    tenant_id: str,
    correlation_id: str,
    stream_name: str,
    event_type: str,
    payload: dict[str, Any],
) -> str:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn(tenant_id) as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    data_dict = (
                        payload.get("data")
                        if isinstance(payload.get("data"), dict)
                        else payload
                    )
                    user_id = data_dict.get("user_id") or payload.get(
                        "user_id", "guest"
                    )
                    query = data_dict.get("user_query") or payload.get("user_query", "")
                    email = payload.get("email") or f"{user_id}@{tenant_id}.local"
                    await cur.execute(
                        "INSERT INTO user_profiles (user_id, tenant_id, email, status) "
                        "VALUES (%s, %s, %s, 'active') "
                        "ON CONFLICT (user_id) DO NOTHING;",
                        (user_id, tenant_id, email),
                    )
                    trip_id = f"trip_{correlation_id}"
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
                return correlation_id
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
    if pool is not None:
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
            return relayed_count
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


async def db_record_login_history(entry_dict: dict[str, Any]) -> str:
    log_id = entry_dict.get("id") or f"log_{uuid.uuid4().hex[:12]}"
    entry_dict["id"] = log_id
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO login_history (id, user_id, provider, ip_address, user_agent, status, suspicious, details) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s);",
                        (
                            log_id,
                            entry_dict["user_id"],
                            entry_dict["provider"],
                            entry_dict["ip_address"],
                            entry_dict["user_agent"],
                            entry_dict["status"],
                            entry_dict.get("suspicious", False),
                            entry_dict.get("details"),
                        ),
                    )
                return log_id
    _in_memory_db["login_history"].append(entry_dict)
    return log_id


async def db_get_login_history(user_id: str, limit: int = 20) -> list[dict[str, Any]]:
    logs = []
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT id, user_id, provider, ip_address, user_agent, status, suspicious, details, timestamp "
                        "FROM login_history WHERE user_id = %s ORDER BY timestamp DESC LIMIT %s;",
                        (user_id, limit),
                    )
                    rows = await cur.fetchall()
                    for row in rows:
                        logs.append(
                            {
                                "id": row[0],
                                "user_id": row[1],
                                "provider": row[2],
                                "ip_address": row[3],
                                "user_agent": row[4],
                                "status": row[5],
                                "suspicious": row[6],
                                "details": row[7],
                                "timestamp": str(row[8]),
                            }
                        )
                    return logs
    return [l for l in _in_memory_db["login_history"] if l.get("user_id") == user_id][
        :limit
    ]


async def db_save_active_session(session_dict: dict[str, Any]) -> str:
    sid = session_dict["session_id"]
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO active_sessions (session_id, user_id, ip_address, user_agent, device_fingerprint, is_trusted, expires_at) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s) "
                        "ON CONFLICT (session_id) DO UPDATE SET last_active_at = NOW();",
                        (
                            sid,
                            session_dict["user_id"],
                            session_dict["ip_address"],
                            session_dict["user_agent"],
                            session_dict.get("device_fingerprint"),
                            session_dict.get("is_trusted", False),
                            session_dict["expires_at"],
                        ),
                    )
                return sid
    _in_memory_db["active_sessions"][sid] = session_dict
    return sid


async def db_get_active_sessions(user_id: str) -> list[dict[str, Any]]:
    sessions = []
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.cursor() as cur:
                    await cur.execute(
                        "SELECT session_id, user_id, ip_address, user_agent, device_fingerprint, is_trusted, created_at, last_active_at, expires_at "
                        "FROM active_sessions WHERE user_id = %s;",
                        (user_id,),
                    )
                    rows = await cur.fetchall()
                    for row in rows:
                        sessions.append(
                            {
                                "session_id": row[0],
                                "user_id": row[1],
                                "ip_address": row[2],
                                "user_agent": row[3],
                                "device_fingerprint": row[4],
                                "is_trusted": row[5],
                                "created_at": str(row[6]),
                                "last_active_at": str(row[7]),
                                "expires_at": str(row[8]),
                            }
                        )
                    return sessions
    return [
        s
        for s in _in_memory_db["active_sessions"].values()
        if s.get("user_id") == user_id
    ]


async def db_delete_active_session(user_id: str, session_id: str) -> bool:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "DELETE FROM active_sessions WHERE session_id = %s AND user_id = %s;",
                        (session_id, user_id),
                    )
                return True
    if session_id in _in_memory_db["active_sessions"]:
        del _in_memory_db["active_sessions"][session_id]
        return True
    return False


async def db_delete_all_sessions(user_id: str) -> int:
    pool = await init_db_pool()
    if pool is not None:
        async with get_tenant_conn() as conn:
            if conn:
                async with conn.transaction(), conn.cursor() as cur:
                    await cur.execute(
                        "DELETE FROM active_sessions WHERE user_id = %s;",
                        (user_id,),
                    )
                return 1
    to_del = [
        sid
        for sid, s in _in_memory_db["active_sessions"].items()
        if s.get("user_id") == user_id
    ]
    for sid in to_del:
        del _in_memory_db["active_sessions"][sid]
    return len(to_del)


# --- Added P0 Identity & Session Helpers ---


async def db_get_user_roles_for_org(
    user_id: str, org_id: str, tenant_id: str = "default"
) -> list[str]:
    """
    Resolves active roles for a user scoped specifically to org_id/tenant_id.
    Includes platform_owner/platform_administrator roles if present, but excludes
    roles belonging exclusively to other organizations.
    """
    roles = set()
    pool = await init_db_pool()
    if pool is not None:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT role FROM org_memberships WHERE user_id = %s AND org_id = %s;",
                    (user_id, org_id),
                )
                r = await cur.fetchone()
                if r and r[0]:
                    roles.add(r[0])
                await cur.execute(
                    "SELECT role, scope_type, scope_id FROM role_assignments WHERE user_id = %s;",
                    (user_id,),
                )
                rows = await cur.fetchall()
                for role_name, scope_type, scope_id in rows:
                    if scope_type == "platform" or scope_type == "organization" and scope_id == org_id or scope_type == "tenant" and (
                        scope_id == tenant_id or not scope_id
                    ):
                        roles.add(role_name)
                await cur.execute(
                    "SELECT roles FROM user_profiles WHERE user_id = %s;",
                    (user_id,),
                )
                prof = await cur.fetchone()
                if prof and prof[0]:
                    prof_roles = (
                        prof[0] if isinstance(prof[0], list) else json.loads(prof[0])
                    )
                    for pr in prof_roles:
                        if pr.lower() in (
                            "platform_owner",
                            "platform_administrator",
                            "admin",
                        ):
                            roles.add(pr)
    else:
        for om in _in_memory_db.get("org_memberships", []):
            if om.get("user_id") == user_id and om.get("org_id") == org_id:
                roles.add(om.get("role", "member"))
        for ra in _in_memory_db.get("role_assignments", []):
            if ra.get("user_id") == user_id:
                st = ra.get("scope_type")
                sid = ra.get("scope_id")
                if st == "platform" or (st == "organization" and sid == org_id):
                    roles.add(ra.get("role"))
        p = _in_memory_db.get("profiles", {}).get(user_id)
        if p and getattr(p, "roles", None):
            for pr in p.roles:
                if pr.lower() in ("platform_owner", "platform_administrator", "admin"):
                    roles.add(pr)

    if not roles:
        roles.add("member")
    return list(roles)


async def db_verify_domain(
    domain: str, org_id: str, verification_token: str = "verified_manual"
) -> None:
    domain_clean = domain.lower().strip()
    pool = await init_db_pool()
    if pool is not None:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO verified_domains (domain, org_id, verification_token, verified, verified_at) "
                    "VALUES (%s, %s, %s, TRUE, NOW()) "
                    "ON CONFLICT (domain) DO UPDATE SET verified = TRUE, verified_at = NOW();",
                    (domain_clean, org_id, verification_token),
                )
            await conn.commit()
    else:
        _in_memory_db.setdefault("verified_domains", {})[domain_clean] = {
            "domain": domain_clean,
            "org_id": org_id,
            "verified": True,
        }


async def db_is_domain_verified(domain: str, org_id: str) -> bool:
    domain_clean = domain.lower().strip()
    pool = await init_db_pool()
    if pool is not None:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT verified FROM verified_domains WHERE domain = %s AND org_id = %s;",
                    (domain_clean, org_id),
                )
                row = await cur.fetchone()
                return bool(row and row[0])
    vd = _in_memory_db.get("verified_domains", {}).get(domain_clean)
    return bool(vd and vd.get("org_id") == org_id and vd.get("verified"))


async def db_save_mfa_factor(
    user_id: str,
    secret_enc: str,
    backup_codes_enc: str,
    mfa_type: str = "totp",
    enabled: bool = True,
) -> None:
    pool = await init_db_pool()
    if pool is not None:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO user_mfa_factors (user_id, secret_encrypted, backup_codes_encrypted, mfa_type, enabled, updated_at) "
                    "VALUES (%s, %s, %s, %s, %s, NOW()) "
                    "ON CONFLICT (user_id) DO UPDATE SET secret_encrypted = EXCLUDED.secret_encrypted, "
                    "backup_codes_encrypted = EXCLUDED.backup_codes_encrypted, mfa_type = EXCLUDED.mfa_type, "
                    "enabled = EXCLUDED.enabled, updated_at = NOW();",
                    (user_id, secret_enc, backup_codes_enc, mfa_type, enabled),
                )
            await conn.commit()
    else:
        _in_memory_db.setdefault("mfa_factors", {})[user_id] = {
            "secret_encrypted": secret_enc,
            "backup_codes_encrypted": backup_codes_enc,
            "mfa_type": mfa_type,
            "enabled": enabled,
        }


async def db_get_mfa_factor(user_id: str) -> dict[str, Any] | None:
    pool = await init_db_pool()
    if pool is not None:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT user_id, secret_encrypted, backup_codes_encrypted, mfa_type, enabled "
                    "FROM user_mfa_factors WHERE user_id = %s;",
                    (user_id,),
                )
                r = await cur.fetchone()
                if r:
                    return {
                        "user_id": r[0],
                        "secret_encrypted": r[1],
                        "backup_codes_encrypted": r[2],
                        "mfa_type": r[3],
                        "enabled": r[4],
                    }
                return None
    return _in_memory_db.get("mfa_factors", {}).get(user_id)


async def db_delete_mfa_factor(user_id: str) -> None:
    pool = await init_db_pool()
    if pool is not None:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "DELETE FROM user_mfa_factors WHERE user_id = %s;", (user_id,)
                )
            await conn.commit()
    else:
        _in_memory_db.get("mfa_factors", {}).pop(user_id, None)


async def db_save_cancellation_token(
    token_hash: str, user_id: str, expires_at: str
) -> None:
    pool = await init_db_pool()
    if pool is not None:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "INSERT INTO deletion_cancellation_tokens (token_hash, user_id, expires_at) "
                    "VALUES (%s, %s, %s) ON CONFLICT (token_hash) DO NOTHING;",
                    (token_hash, user_id, expires_at),
                )
            await conn.commit()
    else:
        _in_memory_db.setdefault("cancellation_tokens", {})[token_hash] = {
            "user_id": user_id,
            "expires_at": expires_at,
        }


async def db_get_cancellation_token(token_hash: str) -> dict[str, Any] | None:
    pool = await init_db_pool()
    if pool is not None:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "SELECT token_hash, user_id, expires_at FROM deletion_cancellation_tokens WHERE token_hash = %s;",
                    (token_hash,),
                )
                r = await cur.fetchone()
                if r:
                    return {"token_hash": r[0], "user_id": r[1], "expires_at": r[2]}
                return None
    return _in_memory_db.get("cancellation_tokens", {}).get(token_hash)


async def db_delete_cancellation_token(token_hash: str) -> None:
    pool = await init_db_pool()
    if pool is not None:
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(
                    "DELETE FROM deletion_cancellation_tokens WHERE token_hash = %s;",
                    (token_hash,),
                )
            await conn.commit()
    else:
        _in_memory_db.get("cancellation_tokens", {}).pop(token_hash, None)
