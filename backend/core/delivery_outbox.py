"""Database-backed at-least-once delivery worker for evidence outbox rows."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import UUID

import structlog
from sqlalchemy import and_, or_, select

from backend.core.shield_engine import Action, DetectionResult, Severity, ShieldVerdict
from backend.models.database import AsyncSessionFactory
from backend.models.models import DeliveryOutbox, DetectionEvent, Tenant

logger = structlog.get_logger(__name__)

MAX_ATTEMPTS = 12
LEASE_SECONDS = 300
BATCH_SIZE = 50


def _enum_value(enum_type, value, default):
    if hasattr(value, "value"):
        value = value.value
    try:
        return enum_type(str(value).lower())
    except (ValueError, TypeError):
        return default


def _safe_confidence(value) -> float:
    try:
        return max(0.0, min(1.0, float(value or 0.0)))
    except (TypeError, ValueError):
        return 0.0


def verdict_from_event(event: DetectionEvent) -> ShieldVerdict:
    """Reconstruct the minimal verdict required by delivery adapters."""
    results = []
    for item in event.results or []:
        if not isinstance(item, dict):
            continue
        details = item.get("details")
        results.append(
            DetectionResult(
                detector=str(item.get("detector", "unknown"))[:64],
                detected=bool(item.get("detected", False)),
                severity=_enum_value(Severity, item.get("severity"), Severity.INFO),
                confidence=_safe_confidence(item.get("confidence", 0.0)),
                details=details if isinstance(details, dict) else {},
                mitre_atlas=[str(value)[:128] for value in (item.get("mitre_atlas") or []) if isinstance(value, str)],
            )
        )
    return ShieldVerdict(
        action=_enum_value(Action, event.action, Action.LOG),
        severity=_enum_value(Severity, event.severity, Severity.INFO),
        blocked=bool(event.blocked),
        results=results,
    )


class DeliveryOutboxWorker:
    """Claim durable work with leases and retry failed deliveries with backoff."""

    def __init__(self, batch_size: int = BATCH_SIZE, max_attempts: int = MAX_ATTEMPTS):
        self.batch_size = max(1, min(batch_size, 500))
        self.max_attempts = max(1, min(max_attempts, 100))

    @staticmethod
    def retry_delay(attempt: int) -> int:
        return min(2 ** max(0, min(attempt, 10)), 3600)

    async def run_once(self) -> int:
        now = datetime.now(timezone.utc)
        stale_before = now - timedelta(seconds=LEASE_SECONDS)
        async with AsyncSessionFactory() as session:
            statement = (
                select(DeliveryOutbox)
                .where(
                    or_(
                        and_(
                            DeliveryOutbox.status == "pending",
                            DeliveryOutbox.available_at <= now,
                        ),
                        and_(
                            DeliveryOutbox.status == "processing",
                            DeliveryOutbox.locked_at.is_not(None),
                            DeliveryOutbox.locked_at < stale_before,
                        ),
                    )
                )
                .order_by(DeliveryOutbox.created_at)
                .limit(self.batch_size)
                .with_for_update(skip_locked=True)
            )
            result = await session.execute(statement)
            rows = list(result.scalars().all())
            for row in rows:
                row.status = "processing"
                row.locked_at = now
                row.attempts += 1
                row.updated_at = now
            await session.commit()
            claimed_ids = [row.id for row in rows]

        for outbox_id in claimed_ids:
            await self._deliver_one(outbox_id)
        return len(claimed_ids)

    async def _deliver_one(self, outbox_id: UUID) -> None:
        async with AsyncSessionFactory() as session:
            row = await session.get(DeliveryOutbox, outbox_id)
            if row is None or row.status != "processing":
                return
            result = await session.execute(
                select(DetectionEvent, Tenant.plan)
                .join(Tenant, Tenant.id == DetectionEvent.tenant_id)
                .where(DetectionEvent.id == row.event_id)
            )
            joined = result.first()
            if joined is None:
                event = None
                plan = "free"
            else:
                event, plan = joined
            delivery_type = row.delivery_type
            tenant_id = str(row.tenant_id)
            attempts = row.attempts
            event_id = row.event_id

        try:
            if event is None:
                raise RuntimeError("outbox_event_missing")
            verdict = verdict_from_event(event)
            if delivery_type == "siem_dispatch":
                from backend.core.siem_dispatch import siem_dispatcher

                results = await siem_dispatcher.dispatch(verdict, tenant_id, plan)
                if not all(results.values()):
                    raise RuntimeError("siem_delivery_failed")
            elif delivery_type == "alert_dispatch":
                from backend.core.siem_dispatch import siem_dispatcher

                results = await siem_dispatcher.dispatch_alert(verdict, tenant_id, plan)
                if not all(results.values()):
                    raise RuntimeError("alert_delivery_failed")
            elif delivery_type == "nis2_dora_evaluate":
                from backend.compliance.nis2_dora import nis2_dora

                succeeded = await nis2_dora.evaluate(verdict, tenant_id, plan, event_id=str(event_id))
                if succeeded is False:
                    raise RuntimeError("compliance_delivery_failed")
            else:
                raise RuntimeError("unknown_delivery_type")
        except Exception as exc:
            now = datetime.now(timezone.utc)
            dead = attempts >= self.max_attempts
            async with AsyncSessionFactory() as session:
                row = await session.get(DeliveryOutbox, outbox_id)
                if row is not None and row.status == "processing":
                    row.status = "dead" if dead else "pending"
                    row.locked_at = None
                    row.available_at = now + timedelta(seconds=self.retry_delay(attempts))
                    row.last_error = type(exc).__name__[:512]
                    row.updated_at = now
                    await session.commit()
            logger.error(
                "outbox_delivery_failed",
                outbox_id=str(outbox_id),
                event_id=str(event_id),
                delivery_type=delivery_type,
                attempts=attempts,
                dead_lettered=dead,
                error_type=type(exc).__name__,
            )
            return

        now = datetime.now(timezone.utc)
        async with AsyncSessionFactory() as session:
            row = await session.get(DeliveryOutbox, outbox_id)
            if row is not None and row.status == "processing":
                row.status = "delivered"
                row.locked_at = None
                row.last_error = None
                row.delivered_at = now
                row.updated_at = now
                await session.commit()
        logger.info(
            "outbox_delivery_succeeded",
            outbox_id=str(outbox_id),
            event_id=str(event_id),
            delivery_type=delivery_type,
            attempts=attempts,
        )

    async def run_forever(self) -> None:
        """Long-running worker loop; task ownership is held by FastAPI lifespan."""
        while True:
            try:
                processed = await self.run_once()
                await asyncio.sleep(1 if processed else 5)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("outbox_worker_iteration_failed", error_type=type(exc).__name__)
                await asyncio.sleep(5)
