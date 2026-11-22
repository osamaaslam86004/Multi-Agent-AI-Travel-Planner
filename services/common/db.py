"""
Postgres Database connection pool management, tenant RLS context setting,
and transactional operations for trips, identity tables, event audit, LLM usage ledger, and outbox.
FinOps persistence for token usage, cost estimates, model, and provider.
"""

import contextlib
import json
import logging
from collections.abc import AsyncGenerator
from typing import Any

import psycopg
from psycopg_pool import AsyncConnectionPool

_PSYCOPG_ERRORS = (psycopg.Error,)


from services.common.telemetry import record_llm_metrics
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
    "federated_identities": {},
    "login_history": {},
    "orgs": {},
    "org_memberships": {},
    "role_assignments": {},
    "idp_configs": {},
    "scim_tokens": {},
    "scim_groups": {},
}


def calculate_cost(
    provider: str, model: str, prompt_tokens: int, completion_tokens: int
) -> float:
    """Computes estimated cost in USD for LLM inference."""
    p_lower = provider.lower()
    if "groq" in p_lower:
        return (prompt_tokens * 0.59 / 1_000_000.0) + (
            completion_tokens * 0.79 / 1_000_000.0
        )
    elif "gemini" in p_lower:
        return (prompt_tokens * 0.15 / 1_000_000.0) + (
            completion_tokens * 0.60 / 1_000_000.0
        )
    return 0.0


async def init_db_pool() -> Any:
    """Initializes the psycopg_pool connection pool if psycopg is available."""
    global _pool
    if psycopg is None or AsyncConnectionPool is None:
        return None
    if _pool is not None:
        return _pool
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
        await init_identity_schema()
        return _pool
    except (ImportError, OSError, RuntimeError, ValueError, Exception) as exc:
        logger.warning(
            f"Postgres pool initialization unavailable: {exc}. Using fallback in-memory database store."
        )
        _pool = None
        return None


async def init_identity_schema() -> None:
    """Creates Phase 2 Identity DDL tables if they do not exist."""
    if _pool is None:
        return
    try:
        async with _pool.connection() as conn, conn.cursor() as cur:
            await cur.execute("""
            CREATE TABLE IF NOT EXISTS orgs (
                org_id VARCHAR(128) PRIMARY KEY,
                org_name VARCHAR(255) NOT NULL,
                tenant_id VARCHAR(128) NOT NULL DEFAULT 'default',
                sso_enforced BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS user_profiles (
                user_id VARCHAR(128) PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                display_name VARCHAR(255),
                avatar_url TEXT,
                bio TEXT,
                timezone VARCHAR(64) DEFAULT 'UTC',
                preferred_currency VARCHAR(16) DEFAULT 'USD',
                status VARCHAR(32) DEFAULT 'active',
                tenant_id VARCHAR(128) NOT NULL DEFAULT 'default',
                org_id VARCHAR(128) REFERENCES orgs(org_id),
                roles JSONB DEFAULT '["member"]'::jsonb,
                email_verified BOOLEAN DEFAULT FALSE,
                mfa_enabled BOOLEAN DEFAULT FALSE,
                mfa_secret VARCHAR(255),
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS federated_identities (
                id VARCHAR(128) PRIMARY KEY,
                user_id VARCHAR(128) REFERENCES user_profiles(user_id) ON DELETE CASCADE,
                provider VARCHAR(64) NOT NULL,
                issuer VARCHAR(255),
                provider_sub VARCHAR(255) NOT NULL,
                tenant_id VARCHAR(128) DEFAULT 'default',
                email VARCHAR(255),
                linked_at TIMESTAMPTZ DEFAULT NOW(),
                CONSTRAINT unique_fed_identity UNIQUE (provider, issuer, provider_sub)
            );

            CREATE TABLE IF NOT EXISTS login_history (
                id VARCHAR(128) PRIMARY KEY,
                user_id VARCHAR(128) REFERENCES user_profiles(user_id) ON DELETE CASCADE,
                tenant_id VARCHAR(128) DEFAULT 'default',
                timestamp TIMESTAMPTZ DEFAULT NOW(),
                provider VARCHAR(64),
                ip_address VARCHAR(64),
                user_agent TEXT,
                status VARCHAR(32),
                suspicious BOOLEAN DEFAULT FALSE,
                details TEXT
            );

            CREATE TABLE IF NOT EXISTS org_memberships (
                id VARCHAR(128) PRIMARY KEY,
                org_id VARCHAR(128) REFERENCES orgs(org_id) ON DELETE CASCADE,
                user_id VARCHAR(128) REFERENCES user_profiles(user_id) ON DELETE CASCADE,
                role VARCHAR(64) DEFAULT 'member',
                tenant_id VARCHAR(128) DEFAULT 'default',
                created_at TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS role_assignments (
                id VARCHAR(128) PRIMARY KEY,
                user_id VARCHAR(128) REFERENCES user_profiles(user_id) ON DELETE CASCADE,
                role VARCHAR(64) NOT NULL,
                scope VARCHAR(64) DEFAULT 'tenant',
                org_id VARCHAR(128),
                tenant_id VARCHAR(128) DEFAULT 'default',
                assigned_by VARCHAR(128),
                assigned_at TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS idp_configs (
                org_id VARCHAR(128) PRIMARY KEY REFERENCES orgs(org_id) ON DELETE CASCADE,
                idp_name VARCHAR(255) NOT NULL,
                sso_type VARCHAR(32) NOT NULL,
                issuer_url TEXT NOT NULL,
                client_id VARCHAR(255) NOT NULL,
                client_secret TEXT,
                metadata_xml TEXT,
                enforce_sso BOOLEAN DEFAULT FALSE,
                allowed_domains JSONB DEFAULT '[]'::jsonb,
                group_role_mappings JSONB DEFAULT '{}'::jsonb,
                tenant_id VARCHAR(128) DEFAULT 'default',
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS scim_tokens (
                token_id VARCHAR(128) PRIMARY KEY,
                org_id VARCHAR(128) REFERENCES orgs(org_id) ON DELETE CASCADE,
                token_hash VARCHAR(255) NOT NULL,
                tenant_id VARCHAR(128) DEFAULT 'default',
                created_at TIMESTAMPTZ DEFAULT NOW(),
                expires_at TIMESTAMPTZ
            );

            CREATE TABLE IF NOT EXISTS scim_groups (
                group_id VARCHAR(128) PRIMARY KEY,
                org_id VARCHAR(128),
                display_name VARCHAR(255) NOT NULL,
                members JSONB DEFAULT '[]'::jsonb,
                tenant_id VARCHAR(128) DEFAULT 'default',
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );
            """)
            await conn.commit()
            logger.info("Validated/created Phase 2 identity schema in Postgres.")
    except Exception as exc:
        logger.warning(f"Error creating identity schema tables: {exc}")


async def close_db_pool() -> None:
    """Closes the Postgres pool."""
    global _pool
    if _pool is not None:
        try:
            await _pool.close()
        except _DB_ERRORS as exc:
            logger.debug(f"Error closing Postgres pool: {exc}")
        _pool = None


@contextlib.asynccontextmanager
async def get_tenant_conn(tenant_id: str = "default") -> AsyncGenerator[Any, None]:
    """Yields active connection with tenant RLS set."""
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
    """Writes trip record and outbox entry in Postgres transaction."""
    async with get_tenant_conn(tenant_id) as conn:
        if conn:
            try:
                async with conn.transaction(), conn.cursor() as cur:
                    user_id = payload.get("user_id", "guest")
                    await cur.execute(
                        "INSERT INTO user_profiles (user_id, email, tenant_id) VALUES (%s, %s, %s) "
                        "ON CONFLICT (user_id) DO NOTHING;",
                        (user_id, f"{user_id}@{tenant_id}.local", tenant_id),
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
    """Relays unprocessed outbox messages to Redis Streams."""
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


async def upsert_trip_result(
    tenant_id: str,
    user_id: str,
    correlation_id: str,
    user_query: str,
    flight_results: str,
    hotel_results: str,
    weather_results: str,
    itinerary: str,
    final_response: str,
    flight_degraded: bool = False,
    hotel_degraded: bool = False,
    weather_degraded: bool = False,
) -> None:
    async with get_tenant_conn(tenant_id) as conn:
        if conn:
            try:
                trip_id = f"trip_{correlation_id}"
                async with conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO user_profiles (user_id, email, tenant_id) VALUES (%s, %s, %s) "
                        "ON CONFLICT (user_id) DO NOTHING;",
                        (user_id, f"{user_id}@{tenant_id}.local", tenant_id),
                    )
                    await cur.execute(
                        """
                        INSERT INTO trips (
                            trip_id, tenant_id, user_id, correlation_id, user_query, status,
                            itinerary, final_response, flight_results, hotel_results, weather_results,
                            flight_degraded, hotel_degraded, weather_degraded, updated_at
                        )
                        VALUES (%s, %s, %s, %s, %s, 'DONE', %s, %s, %s, %s, %s, %s, %s, %s, NOW())
                        ON CONFLICT (correlation_id) DO UPDATE SET
                            status = 'DONE',
                            itinerary = EXCLUDED.itinerary,
                            final_response = EXCLUDED.final_response,
                            flight_results = EXCLUDED.flight_results,
                            hotel_results = EXCLUDED.hotel_results,
                            weather_results = EXCLUDED.weather_results,
                            flight_degraded = EXCLUDED.flight_degraded,
                            hotel_degraded = EXCLUDED.hotel_degraded,
                            weather_degraded = EXCLUDED.weather_degraded,
                            updated_at = NOW();
                        """,
                        (
                            trip_id,
                            tenant_id,
                            user_id,
                            correlation_id,
                            user_query,
                            itinerary,
                            final_response,
                            flight_results,
                            hotel_results,
                            weather_results,
                            flight_degraded,
                            hotel_degraded,
                            weather_degraded,
                        ),
                    )
                await conn.commit()
                logger.info(f"Upserted trip '{correlation_id}' to Postgres.")
            except _DB_ERRORS as exc:
                logger.error(f"Failed upserting trip result to DB: {exc}")
    _in_memory_db["trips"][correlation_id] = {
        "correlation_id": correlation_id,
        "tenant_id": tenant_id,
        "user_id": user_id,
        "user_query": user_query,
        "status": "DONE",
        "itinerary": itinerary,
        "final_response": final_response,
        "flight_results": flight_results,
        "hotel_results": hotel_results,
        "weather_results": weather_results,
        "flight_degraded": flight_degraded,
        "hotel_degraded": hotel_degraded,
        "weather_degraded": weather_degraded,
    }


async def record_trip_event(
    tenant_id: str, correlation_id: str, event_type: str, payload: dict[str, Any]
) -> None:
    async with get_tenant_conn(tenant_id) as conn:
        if conn:
            try:
                trip_id = f"trip_{correlation_id}"
                async with conn.cursor() as cur:
                    await cur.execute(
                        "INSERT INTO trip_events (trip_id, correlation_id, tenant_id, event_type, payload) "
                        "VALUES (%s, %s, %s, %s, %s::jsonb);",
                        (
                            trip_id,
                            correlation_id,
                            tenant_id,
                            event_type,
                            json.dumps(payload),
                        ),
                    )
                await conn.commit()
            except _DB_ERRORS as exc:
                logger.debug(f"Failed recording trip event audit log: {exc}")
    _in_memory_db["trip_events"].append(
        {
            "tenant_id": tenant_id,
            "correlation_id": correlation_id,
            "event_type": event_type,
            "payload": payload,
        }
    )


async def record_llm_usage(
    tenant_id: str,
    user_id: str,
    correlation_id: str,
    provider: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
    latency_ms: float = 0.0,
    cost_estimate: float = 0.0,
) -> None:
    final_cost = (
        cost_estimate
        if cost_estimate > 0.0
        else calculate_cost(provider, model, prompt_tokens, completion_tokens)
    )
    async with get_tenant_conn(tenant_id) as conn:
        if conn:
            try:
                trip_id = f"trip_{correlation_id}"
                async with conn.cursor() as cur:
                    await cur.execute(
                        """
                        INSERT INTO llm_usage (
                            tenant_id, user_id, trip_id, correlation_id, provider, model,
                            prompt_tokens, completion_tokens, total_tokens, latency_ms, cost_estimate
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                        """,
                        (
                            tenant_id,
                            user_id,
                            trip_id,
                            correlation_id,
                            provider,
                            model,
                            prompt_tokens,
                            completion_tokens,
                            total_tokens,
                            latency_ms,
                            final_cost,
                        ),
                    )
                await conn.commit()
            except _DB_ERRORS as exc:
                logger.debug(f"Failed recording LLM usage ledger: {exc}")
    _in_memory_db["llm_usage"].append(
        {
            "tenant_id": tenant_id,
            "user_id": user_id,
            "correlation_id": correlation_id,
            "provider": provider,
            "model": model,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "latency_ms": latency_ms,
            "cost_estimate": final_cost,
        }
    )
    record_llm_metrics(
        tenant_id=tenant_id,
        provider=provider,
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        cost_estimate=final_cost,
    )


async def get_tenant_total_tokens_today(tenant_id: str) -> int:
    pool = await init_db_pool()
    if pool:
        try:
            async with pool.connection() as conn, conn.cursor() as cur:
                await cur.execute(
                    "SELECT COALESCE(SUM(total_tokens), 0) FROM llm_usage "
                    "WHERE tenant_id = %s AND created_at >= CURRENT_DATE;",
                    (tenant_id,),
                )
                row = await cur.fetchone()
                if row:
                    return int(row[0])
        except _DB_ERRORS:
            pass
    total = sum(
        item["total_tokens"]
        for item in _in_memory_db["llm_usage"]
        if item.get("tenant_id") == tenant_id
    )
    return total


async def get_trip_by_id(
    correlation_id: str, tenant_id: str = "default"
) -> dict[str, Any] | None:
    async with get_tenant_conn(tenant_id) as conn:
        if conn:
            try:
                async with conn.cursor() as cur:
                    await cur.execute(
                        """
                        SELECT trip_id, tenant_id, user_id, correlation_id, user_query, status,
                               itinerary, final_response, flight_results, hotel_results, weather_results,
                               flight_degraded, hotel_degraded, weather_degraded, created_at, updated_at
                        FROM trips
                        WHERE correlation_id = %s AND tenant_id = %s;
                        """,
                        (correlation_id, tenant_id),
                    )
                    row = await cur.fetchone()
                    if row:
                        return {
                            "trip_id": row[0],
                            "tenant_id": row[1],
                            "user_id": row[2],
                            "correlation_id": row[3],
                            "user_query": row[4],
                            "status": row[5],
                            "itinerary": row[6],
                            "final_response": row[7],
                            "flight_results": row[8],
                            "hotel_results": row[9],
                            "weather_results": row[10],
                            "flight_degraded": row[11],
                            "hotel_degraded": row[12],
                            "weather_degraded": row[13],
                            "created_at": str(row[14]),
                            "updated_at": str(row[15]),
                        }
            except _DB_ERRORS as exc:
                logger.debug(f"Error fetching trip from DB: {exc}")
    mem_trip = _in_memory_db["trips"].get(correlation_id)
    if mem_trip and mem_trip.get("tenant_id") == tenant_id:
        return mem_trip
    return None
