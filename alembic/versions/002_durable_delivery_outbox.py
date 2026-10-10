"""Durable transactional outbox for SIEM and compliance delivery.

Revision ID: 002_durable_delivery_outbox
Revises: 001_initial_schema
"""
from __future__ import annotations

import uuid

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "002_durable_delivery_outbox"
down_revision = "001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "delivery_outbox",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("detection_events.id"), nullable=False),
        sa.Column("delivery_type", sa.String(64), nullable=False),
        sa.Column("dedupe_key", sa.String(255), nullable=False, unique=True),
        sa.Column("payload", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("event_id", "delivery_type", name="uq_delivery_outbox_event_type"),
    )
    op.create_index("ix_delivery_outbox_ready", "delivery_outbox", ["status", "available_at"])
    op.create_index("ix_delivery_outbox_tenant_created", "delivery_outbox", ["tenant_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_delivery_outbox_tenant_created", table_name="delivery_outbox")
    op.drop_index("ix_delivery_outbox_ready", table_name="delivery_outbox")
    op.drop_table("delivery_outbox")
