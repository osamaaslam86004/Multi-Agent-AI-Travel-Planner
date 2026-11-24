"""Phase 2 Identity and Auth Schema Migration

Revision ID: 001_phase2_identity
Revises:
Create Date: 2026-11-24 00:00:00.000000

"""

from collections.abc import Sequence

from alembic import op

revision: str = "001_phase2_identity"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
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
    CREATE INDEX IF NOT EXISTS idx_user_profiles_email_lower ON user_profiles ((LOWER(email)));
    CREATE INDEX IF NOT EXISTS idx_user_profiles_tenant ON user_profiles (tenant_id);
    CREATE INDEX IF NOT EXISTS idx_login_history_user_time ON login_history (user_id, timestamp DESC);
    CREATE INDEX IF NOT EXISTS idx_federated_identities_user ON federated_identities (user_id);
    CREATE INDEX IF NOT EXISTS idx_org_invitations_email ON org_invitations ((LOWER(email)));
    CREATE INDEX IF NOT EXISTS idx_scim_users_org ON scim_users (org_id);
    CREATE INDEX IF NOT EXISTS idx_scim_groups_org ON scim_groups (org_id);
    CREATE INDEX IF NOT EXISTS idx_role_assignments_user ON role_assignments (user_id);
    CREATE INDEX IF NOT EXISTS idx_org_memberships_user ON org_memberships (user_id);
    """)


def downgrade() -> None:
    pass
