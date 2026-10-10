"""Unit tests for durable evidence and delivery outbox behavior."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
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
    assert awaitable_called(session.commit)
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


def awaitable_called(mock):
    return mock.await_count == 1
