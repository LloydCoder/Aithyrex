"""Initial schema — tenants, detection_events, usage_counters, alerts

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-06-16
"""

from __future__ import annotations

import uuid
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── tenants ───────────────────────────────────────────────────────────────
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("clerk_org_id", sa.String(128), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("plan", sa.String(32), nullable=False, server_default="free"),
        sa.Column("lemonsqueezy_customer_id", sa.String(128), nullable=True),
        sa.Column("paddle_customer_id", sa.String(128), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="true"),
        sa.Column("block_mode_enabled", sa.Boolean(), server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_tenants_clerk_org_id", "tenants", ["clerk_org_id"])

    # ── detection_events ──────────────────────────────────────────────────────
    op.create_table(
        "detection_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("model", sa.String(128), nullable=True),
        sa.Column("prompt_len", sa.Integer(), server_default="0"),
        sa.Column("completion_len", sa.Integer(), server_default="0"),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("blocked", sa.Boolean(), server_default="false"),
        sa.Column("results", postgresql.JSONB(), server_default="[]"),
        sa.Column("siem_exported", sa.Boolean(), server_default="false"),
        sa.Column("compliance_notified", sa.Boolean(), server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
    )
    op.create_index("ix_detection_events_tenant_created", "detection_events", ["tenant_id", "created_at"])
    op.create_index("ix_detection_events_action", "detection_events", ["action"])
    op.create_index("ix_detection_events_severity", "detection_events", ["severity"])

    # ── usage_counters ────────────────────────────────────────────────────────
    op.create_table(
        "usage_counters",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("year", sa.Integer(), nullable=False),
        sa.Column("month", sa.Integer(), nullable=False),
        sa.Column("inferences_used", sa.BigInteger(), server_default="0"),
        sa.Column("inferences_limit", sa.BigInteger(), server_default="500"),
        sa.Column("blocked_count", sa.BigInteger(), server_default="0"),
        sa.Column("alerted_count", sa.BigInteger(), server_default="0"),
        sa.Column("overage_inferences", sa.BigInteger(), server_default="0"),
        sa.Column("overage_billed", sa.Boolean(), server_default="false"),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_usage_tenant_month", "usage_counters", ["tenant_id", "year", "month"], unique=True)

    # ── alerts ────────────────────────────────────────────────────────────────
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("detection_events.id"), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("detector", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("mitre_atlas", postgresql.JSONB(), server_default="[]"),
        sa.Column("details", postgresql.JSONB(), server_default="{}"),
        sa.Column("acknowledged", sa.Boolean(), server_default="false"),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("slack_notified", sa.Boolean(), server_default="false"),
        sa.Column("webhook_notified", sa.Boolean(), server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
    )
    op.create_index("ix_alerts_tenant_created", "alerts", ["tenant_id", "created_at"])
    op.create_index("ix_alerts_unacknowledged", "alerts", ["tenant_id", "acknowledged"])


def downgrade() -> None:
    op.drop_table("alerts")
    op.drop_table("usage_counters")
    op.drop_table("detection_events")
    op.drop_table("tenants")
