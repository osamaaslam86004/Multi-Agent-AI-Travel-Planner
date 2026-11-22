-- Phase 2 Enterprise Identity, Access & Account Management Migration
-- DDL Schema for Orgs, User Profiles, Federated Identities, Login History,
-- Org Memberships, Role Assignments, IdP Configurations, SCIM Tokens, and SCIM Groups.

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

-- Enable Row-Level Security (RLS) policies for tenant scoping
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE login_history ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_profiles_tenant_isolation ON user_profiles
    USING (tenant_id = current_setting('app.current_tenant_id', true));
