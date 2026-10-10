"""Unit tests for durable evidence and delivery outbox behavior."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from backend.core.delivery_outbox import DeliveryOutboxWorker, verdict_from_event
from backend.core.event_logger import EventLogger
from backend.core.shield_engine import Action, DetectionResult, Severity


def test_retry_delay_is_exponential_and_bounded():
    assert DeliveryOutboxWorker.retry_delay(0) == 1
    assert DeliveryOutboxWorker.retry_delay(4) == 16
    assert DeliveryOutboxWorker.retry_delay(99) == 1024


def test_verdict_reconstruction_uses_safe_enum_fallbacks():
    event = SimpleNamespace(
        action="block",
        severity="critical",
        blocked=True,
        results=[
            {
                "detector": "credential_leak",
                "detected": True,
                "severity": "critical",
                "confidence": 0.98,
                "mitre_atlas": ["AML.T0051"],
                "details": {"kind": "credential"},
            },
            {"detector": "bad", "detected": False, "severity": "unknown", "confidence": 2.0},
        ],
    )
    verdict = verdict_from_event(event)
    assert verdict.action == Action.BLOCK
    assert verdict.severity == Severity.CRITICAL
    assert verdict.blocked is True
    assert verdict.results[0].severity == Severity.CRITICAL
    assert verdict.results[0].details == {"kind": "credential"}
    assert verdict.results[1].severity == Severity.INFO
    assert verdict.results[1].confidence == 1.0


@pytest.mark.asyncio
async def test_event_and_delivery_intents_commit_in_one_transaction(monkeypatch):
    tenant_id = uuid.uuid4()
    session = SimpleNamespace(added=[], commit=AsyncMock())

    def add(value):
        session.added.append(value)

    session.add = add

    class SessionContext:
        async def __aenter__(self):
            return session

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(
        "backend.models.database.AsyncSessionFactory",
        lambda: SessionContext(),
    )
    verdict = SimpleNamespace(
        action=Action.ALERT,
        severity=Severity.HIGH,
        blocked=False,
        results=[
            DetectionResult(
                detector="prompt_injection",
                detected=True,
                severity=Severity.HIGH,
                confidence=0.9,
                details={"rule": "injection"},
                mitre_atlas=["AML.T0051"],
            )
        ],
    )

    event_id = await EventLogger().log_event(
        verdict=verdict,
        tenant_id=str(tenant_id),
        model="test-model",
        prompt_len=120,
        completion_len=10,
    )

    from backend.models.models import Alert, DeliveryOutbox, DetectionEvent

    assert event_id is not None
    assert session.commit.await_count == 1
    event_rows = [row for row in session.added if isinstance(row, DetectionEvent)]
    alert_rows = [row for row in session.added if isinstance(row, Alert)]
    outbox_rows = [row for row in session.added if isinstance(row, DeliveryOutbox)]
    assert len(event_rows) == 1
    assert len(alert_rows) == 1
    assert {row.delivery_type for row in outbox_rows} == {
        "siem_dispatch", "alert_dispatch", "nis2_dora_evaluate"
    }
    assert all(row.event_id == event_rows[0].id for row in outbox_rows)
    assert len({row.dedupe_key for row in outbox_rows}) == 3


@pytest.mark.asyncio
async def test_worker_claims_rows_with_a_lease_and_dispatches(monkeypatch):
    now = datetime.now(timezone.utc)
    row = SimpleNamespace(
        id=uuid.uuid4(),
        status="pending",
        available_at=now - timedelta(seconds=1),
        created_at=now,
        attempts=0,
        locked_at=None,
        updated_at=now,
    )
    session = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(
            scalars=lambda: SimpleNamespace(all=lambda: [row])
        )),
        commit=AsyncMock(),
    )

    class SessionContext:
        async def __aenter__(self):
            return session

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(
        "backend.core.delivery_outbox.AsyncSessionFactory",
        lambda: SessionContext(),
    )
    worker = DeliveryOutboxWorker(batch_size=1)
    worker._deliver_one = AsyncMock()
    claimed = await worker.run_once()
    assert claimed == 1
    assert row.status == "processing"
    assert row.attempts == 1
    assert row.locked_at is not None
    assert session.commit.await_count == 1
    worker._deliver_one.assert_awaited_once_with(row.id)


@pytest.mark.asyncio
async def test_failed_delivery_is_requeued_without_sensitive_error_text(monkeypatch):
    now = datetime.now(timezone.utc)
    outbox_row = SimpleNamespace(
        id=uuid.uuid4(),
        event_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        delivery_type="siem_dispatch",
        status="processing",
        attempts=1,
        locked_at=now,
        available_at=now,
        last_error=None,
        updated_at=now,
    )
    event = SimpleNamespace(
        action="log",
        severity="high",
        blocked=False,
        results=[{
            "detector": "prompt_injection",
            "detected": True,
            "severity": "high",
            "confidence": 0.9,
            "details": {},
            "mitre_atlas": [],
        }],
    )
    session = SimpleNamespace(
        get=AsyncMock(side_effect=[outbox_row, outbox_row]),
        execute=AsyncMock(return_value=SimpleNamespace(first=lambda: (event, "pro"))),
        commit=AsyncMock(),
    )

    class SessionContext:
        async def __aenter__(self):
            return session

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(
        "backend.core.delivery_outbox.AsyncSessionFactory",
        lambda: SessionContext(),
    )
    from backend.core.siem_dispatch import siem_dispatcher

    monkeypatch.setattr(
        siem_dispatcher, "dispatch", AsyncMock(return_value={"hec": False})
    )
    await DeliveryOutboxWorker()._deliver_one(outbox_row.id)
    assert outbox_row.status == "pending"
    assert outbox_row.last_error == "RuntimeError"
    assert outbox_row.locked_at is None
    assert outbox_row.available_at > now
    assert session.commit.await_count == 1
