-- Phase 3 Postgres Schema with Row-Level Security (RLS)
-- Tables: tenants, users, trips, trip_events (append-only audit), llm_usage, outbox

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Default Tenant Insertion
INSERT INTO tenants (tenant_id, name)
VALUES ('default', 'Default Organization Tenant')
ON CONFLICT (tenant_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT,
    roles TEXT[] DEFAULT '{traveler}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trips (
    trip_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    correlation_id VARCHAR(128) UNIQUE NOT NULL,
    user_query TEXT NOT NULL,
    status VARCHAR(32) DEFAULT 'GATHERING',
    itinerary TEXT,
    final_response TEXT,
    flight_results TEXT,
    hotel_results TEXT,
    weather_results TEXT,
    flight_degraded BOOLEAN DEFAULT FALSE,
    hotel_degraded BOOLEAN DEFAULT FALSE,
    weather_degraded BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS trip_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trip_id VARCHAR(64),
    correlation_id VARCHAR(128) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    event_type VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS llm_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    user_id VARCHAR(64),
    trip_id VARCHAR(64),
    correlation_id VARCHAR(128) NOT NULL,
    provider VARCHAR(64) NOT NULL,
    model VARCHAR(64) NOT NULL,
    prompt_tokens INT DEFAULT 0,
    completion_tokens INT DEFAULT 0,
    total_tokens INT DEFAULT 0,
    latency_ms DOUBLE PRECISION DEFAULT 0.0,
    cost_estimate DOUBLE PRECISION DEFAULT 0.0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    correlation_id VARCHAR(128) NOT NULL,
    stream_name VARCHAR(128) NOT NULL,
    event_type VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL,
    processed BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    processed_at TIMESTAMPTZ
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_trips_correlation ON trips(correlation_id);
CREATE INDEX IF NOT EXISTS idx_trips_tenant_user ON trips(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_trip_events_correlation ON trip_events(correlation_id);
CREATE INDEX IF NOT EXISTS idx_llm_usage_correlation ON llm_usage(correlation_id);
CREATE INDEX IF NOT EXISTS idx_outbox_unprocessed ON outbox(processed, created_at) WHERE processed = FALSE;

-- Enable Row-Level Security (RLS) on tenant_id
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE trips ENABLE ROW LEVEL SECURITY;
ALTER TABLE trip_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE llm_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE outbox ENABLE ROW LEVEL SECURITY;

-- Security Policies enforcing current tenant context
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_users') THEN
        CREATE POLICY tenant_isolation_users ON users
            USING (tenant_id = current_setting('app.current_tenant_id', true) OR current_setting('app.current_tenant_id', true) IS NULL OR current_setting('app.current_tenant_id', true) = '');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_trips') THEN
        CREATE POLICY tenant_isolation_trips ON trips
            USING (tenant_id = current_setting('app.current_tenant_id', true) OR current_setting('app.current_tenant_id', true) IS NULL OR current_setting('app.current_tenant_id', true) = '');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_events') THEN
        CREATE POLICY tenant_isolation_events ON trip_events
            USING (tenant_id = current_setting('app.current_tenant_id', true) OR current_setting('app.current_tenant_id', true) IS NULL OR current_setting('app.current_tenant_id', true) = '');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_usage') THEN
        CREATE POLICY tenant_isolation_usage ON llm_usage
            USING (tenant_id = current_setting('app.current_tenant_id', true) OR current_setting('app.current_tenant_id', true) IS NULL OR current_setting('app.current_tenant_id', true) = '');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'tenant_isolation_outbox') THEN
        CREATE POLICY tenant_isolation_outbox ON outbox
            USING (tenant_id = current_setting('app.current_tenant_id', true) OR current_setting('app.current_tenant_id', true) IS NULL OR current_setting('app.current_tenant_id', true) = '');
    END IF;
END $$;
