"""
AI Shield — Database Models
=============================
SQLAlchemy 2.0 async models.

Tables:
  tenants         — multi-tenant isolation (Clerk org → tenant)
  detection_events — every inspect() call logged here
  usage_counters  — monthly inference count per tenant (tier enforcement)
  alerts          — events that triggered ALERT or BLOCK actions
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger, Boolean, DateTime, Float,
    ForeignKey, Index, Integer, String, Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# ── Tenants ───────────────────────────────────────────────────────────────────
class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    clerk_org_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Billing
    plan: Mapped[str] = mapped_column(
        String(32), nullable=False, default="free"
    )  # free | starter | pro | enterprise
    lemonsqueezy_customer_id: Mapped[str | None] = mapped_column(String(128))
    paddle_customer_id: Mapped[str | None] = mapped_column(String(128))

    # State
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    block_mode_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    # Relationships
    events: Mapped[list[DetectionEvent]] = relationship(back_populates="tenant")
    usage: Mapped[list[UsageCounter]] = relationship(back_populates="tenant")
    alerts: Mapped[list[Alert]] = relationship(back_populates="tenant")

    def __repr__(self) -> str:
        return f"<Tenant {self.name} plan={self.plan}>"


# ── Detection Events ──────────────────────────────────────────────────────────
class DetectionEvent(Base):
    __tablename__ = "detection_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False
    )

    # Inference metadata
    model: Mapped[str | None] = mapped_column(String(128))
    prompt_len: Mapped[int] = mapped_column(Integer, default=0)
    completion_len: Mapped[int] = mapped_column(Integer, default=0)

    # Verdict
    action: Mapped[str] = mapped_column(String(16))   # pass | log | alert | block
    severity: Mapped[str] = mapped_column(String(16))  # clean | info | low | medium | high | critical
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)

    # Full detector results stored as JSONB
    results: Mapped[dict] = mapped_column(JSONB, default=list)

    # SIEM export tracking
    siem_exported: Mapped[bool] = mapped_column(Boolean, default=False)
    compliance_notified: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )

    # Relationship
    tenant: Mapped[Tenant] = relationship(back_populates="events")

    __table_args__ = (
        Index("ix_detection_events_tenant_created", "tenant_id", "created_at"),
        Index("ix_detection_events_action", "action"),
        Index("ix_detection_events_severity", "severity"),
    )


# ── Usage Counters ────────────────────────────────────────────────────────────
class UsageCounter(Base):
    """
    Monthly inference counter per tenant.
    Enforces Free (500), Starter (25K), Pro (150K) limits.
    Overage billing calculated from these records.
    """

    __tablename__ = "usage_counters"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False
    )

    year: Mapped[int] = mapped_column(Integer, nullable=False)
    month: Mapped[int] = mapped_column(Integer, nullable=False)   # 1–12

    # Counts
    inferences_used: Mapped[int] = mapped_column(BigInteger, default=0)
    inferences_limit: Mapped[int] = mapped_column(BigInteger, default=500)
    blocked_count: Mapped[int] = mapped_column(BigInteger, default=0)
    alerted_count: Mapped[int] = mapped_column(BigInteger, default=0)

    # Overage
    overage_inferences: Mapped[int] = mapped_column(BigInteger, default=0)
    overage_billed: Mapped[bool] = mapped_column(Boolean, default=False)

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    tenant: Mapped[Tenant] = relationship(back_populates="usage")

    __table_args__ = (
        Index("ix_usage_tenant_month", "tenant_id", "year", "month", unique=True),
    )


# ── Alerts ────────────────────────────────────────────────────────────────────
class Alert(Base):
    """
    HIGH and CRITICAL events that need human attention.
    Feeds the dashboard alert feed and WebSocket stream.
    """

    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("detection_events.id"), nullable=False
    )

    severity: Mapped[str] = mapped_column(String(16))
    detector: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[float] = mapped_column(Float)
    mitre_atlas: Mapped[list] = mapped_column(JSONB, default=list)
    details: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Response tracking
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Notifications sent
    slack_notified: Mapped[bool] = mapped_column(Boolean, default=False)
    webhook_notified: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )

    tenant: Mapped[Tenant] = relationship(back_populates="alerts")

    __table_args__ = (
        Index("ix_alerts_tenant_created", "tenant_id", "created_at"),
        Index("ix_alerts_unacknowledged", "tenant_id", "acknowledged"),
    )
