"""Phase 2 Enterprise Identity & Access Management Schema Migration

Revision ID: 002_phase2_enterprise_identity
Revises: 001_initial_schema
Create Date: 2026-11-23 13:30:00.000000

"""

import sqlalchemy as sa
from alembic import op

revision = "002_phase2_enterprise_identity"
down_revision = "001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "org_invitations",
        sa.Column("token", sa.String(128), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("orgs.org_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("role", sa.String(64), server_default="member", nullable=False),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now()
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("accepted", sa.Boolean(), server_default="false"),
    )
    op.add_column(
        "user_profiles",
        sa.Column("deletion_requested_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "user_profiles",
        sa.Column("deletion_scheduled_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("user_profiles", "deletion_scheduled_at")
    op.drop_column("user_profiles", "deletion_requested_at")
    op.drop_table("org_invitations")
