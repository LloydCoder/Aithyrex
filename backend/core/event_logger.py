"""
AI Shield — Event Logger
=========================
Persists every detection event to PostgreSQL.
Also creates Alert records for HIGH and CRITICAL verdicts.
Updates UsageCounter in DB for monthly billing reconciliation.

Runs as a background task — never blocks the HTTP response.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

import structlog

logger = structlog.get_logger(__name__)


class EventLogger:
    """
    Background service that persists detection events to DB.

    Called via asyncio.create_task() — fire and forget.
    If DB is unavailable, logs to structlog and continues.
    The Redis usage counter is the source of truth for real-time limits.
    PostgreSQL is the audit trail and billing reconciliation store.
    """

    async def log_event(
        self,
        verdict,
        tenant_id: str,
        model: str | None = None,
        prompt_len: int = 0,
        completion_len: int = 0,
    ) -> str | None:
        """
        Persist a ShieldVerdict to PostgreSQL.

        Returns the event UUID if saved, None if DB unavailable.
        """
        try:
            from backend.models.database import AsyncSessionFactory
            from backend.models.models import Alert, DetectionEvent
            from backend.core.shield_engine import Action, Severity

            event_id = uuid.uuid4()

            async with AsyncSessionFactory() as session:
                # ── Detection event ───────────────────────────────────────
                # Safely parse tenant_id — Clerk dev mode sends non-UUID strings
                try:
                    parsed_tenant_id = uuid.UUID(tenant_id) if isinstance(tenant_id, str) else tenant_id
                except (ValueError, AttributeError):
                    logger.warning("invalid_tenant_uuid_skipping_db_log", tenant_id=tenant_id)
                    return None

                event = DetectionEvent(
                    id=event_id,
                    tenant_id=parsed_tenant_id,
                    model=model,
                    prompt_len=prompt_len,
                    completion_len=completion_len,
                    action=verdict.action,
                    severity=verdict.severity,
                    blocked=verdict.blocked,
                    results=[
                        {
                            "detector": r.detector,
                            "detected": r.detected,
                            "severity": r.severity,
                            "confidence": r.confidence,
                            "mitre_atlas": r.mitre_atlas,
                            "details": r.details,
                        }
                        for r in verdict.results
                    ],
                )
                session.add(event)

                # ── Alert record for HIGH/CRITICAL ────────────────────────
                if verdict.severity in (Severity.HIGH, Severity.CRITICAL):
                    for r in verdict.results:
                        if r.detected and r.severity in (Severity.HIGH, Severity.CRITICAL):
                            alert = Alert(
                                tenant_id=event.tenant_id,
                                event_id=event_id,
                                severity=r.severity,
                                detector=r.detector,
                                confidence=r.confidence,
                                mitre_atlas=r.mitre_atlas,
                                details=r.details,
                            )
                            session.add(alert)

                await session.commit()

                logger.info(
                    "event_logged",
                    event_id=str(event_id),
                    action=verdict.action,
                    severity=verdict.severity,
                    tenant_id=tenant_id,
                )
                return str(event_id)

        except Exception as e:
            # DB errors never crash the detection pipeline
            logger.error("event_log_failed", error=str(e), tenant_id=tenant_id)
            return None

    async def update_db_usage(
        self,
        tenant_id: str,
        year: int,
        month: int,
        plan: str = "free",
    ) -> None:
        """
        Upsert the monthly usage counter in PostgreSQL.
        Called hourly by cron — Redis is source of truth for real-time.
        """
        from backend.core.usage_counter import TIER_LIMITS, usage_counter

        try:
            from backend.models.database import AsyncSessionFactory
            from backend.models.models import UsageCounter
            from sqlalchemy import select

            redis_count = await usage_counter.get_count(tenant_id)
            limit = TIER_LIMITS.get(plan, 500)
            overage = max(0, redis_count - limit)

            try:
                parsed_id = uuid.UUID(tenant_id) if isinstance(tenant_id, str) else tenant_id
            except ValueError:
                logger.warning("invalid_tenant_uuid_skipping_usage_sync", tenant_id=tenant_id)
                return

            async with AsyncSessionFactory() as session:
                stmt = select(UsageCounter).where(
                    UsageCounter.tenant_id == parsed_id,
                    UsageCounter.year == year,
                    UsageCounter.month == month,
                )
                result = await session.execute(stmt)
                counter = result.scalar_one_or_none()

                if counter:
                    counter.inferences_used = redis_count
                    counter.overage_inferences = overage
                else:
                    counter = UsageCounter(
                        tenant_id=parsed_id,
                        year=year,
                        month=month,
                        inferences_used=redis_count,
                        inferences_limit=limit,
                        overage_inferences=overage,
                    )
                    session.add(counter)

                await session.commit()

        except Exception as e:
            logger.error("db_usage_sync_failed", error=str(e), tenant_id=tenant_id)


# Module-level singleton
event_logger = EventLogger()
