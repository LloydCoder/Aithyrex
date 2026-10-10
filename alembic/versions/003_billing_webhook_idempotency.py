"""Idempotent billing webhook event ledger and resource ordering.

Revision ID: 003_billing_webhook_idempotency
Revises: 002_durable_delivery_outbox
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "003_billing_webhook_idempotency"
down_revision = "002_durable_delivery_outbox"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "billing_webhook_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("event_key", sa.String(128), nullable=False),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("resource_id", sa.String(128), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="processing"),
        sa.Column("result", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("provider", "event_key", name="uq_billing_webhook_provider_event"),
    )
    op.create_index(
        "ix_billing_webhook_resource_order",
        "billing_webhook_events",
        ["provider", "resource_id", "occurred_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_billing_webhook_resource_order", table_name="billing_webhook_events")
    op.drop_table("billing_webhook_events")
