import hashlib
import hmac
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from backend.core.billing import (
    BillingService,
    _plan_from_paddle_price,
    verify_lemonsqueezy_signature,
    verify_paddle_signature,
)


def test_missing_lemonsqueezy_secret_rejects_signature(monkeypatch):
    monkeypatch.setattr("backend.core.config.settings", SimpleNamespace(LEMONSQUEEZY_WEBHOOK_SECRET=""))
    assert verify_lemonsqueezy_signature(b"{}", "") is False


def test_missing_paddle_secret_rejects_signature(monkeypatch):
    monkeypatch.setattr("backend.core.config.settings", SimpleNamespace(PADDLE_WEBHOOK_SECRET=""))
    assert verify_paddle_signature(b"{}", "ts=1;h1=abc") is False


def test_paddle_signature_verifies_timestamped_payload(monkeypatch):
    secret = "test-webhook-secret"
    now = int(time.time())
    payload = b'{"event_type":"subscription.updated"}'
    signed = str(now).encode() + b":" + payload
    digest = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    monkeypatch.setattr("backend.core.config.settings", SimpleNamespace(PADDLE_WEBHOOK_SECRET=secret))
    assert verify_paddle_signature(payload, f"ts={now};h1={digest}") is True


def test_paddle_signature_rejects_tampered_payload(monkeypatch):
    secret = "test-webhook-secret"
    now = int(time.time())
    payload = b'{"event_type":"subscription.updated"}'
    signed = str(now).encode() + b":" + payload
    digest = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    monkeypatch.setattr("backend.core.config.settings", SimpleNamespace(PADDLE_WEBHOOK_SECRET=secret))
    assert verify_paddle_signature(payload + b" ", f"ts={now};h1={digest}") is False


def test_paddle_signature_rejects_stale_timestamp(monkeypatch):
    secret = "test-webhook-secret"
    old = int(time.time()) - 3600
    payload = b"{}"
    digest = hmac.new(secret.encode(), str(old).encode() + b":" + payload, hashlib.sha256).hexdigest()
    monkeypatch.setattr("backend.core.config.settings", SimpleNamespace(PADDLE_WEBHOOK_SECRET=secret))
    assert verify_paddle_signature(payload, f"ts={old};h1={digest}") is False


def test_unknown_paddle_price_never_grants_paid_plan(monkeypatch):
    monkeypatch.setattr("backend.core.config.settings", SimpleNamespace(PADDLE_PRO_PRICE_ID="pro-id", PADDLE_ENTERPRISE_PRICE_ID="enterprise-id"))
    assert _plan_from_paddle_price("unexpected-price") is None


def test_empty_provider_price_ids_never_grant_paid_plan(monkeypatch):
    monkeypatch.setattr(
        "backend.core.config.settings",
        SimpleNamespace(PADDLE_PRO_PRICE_ID="", PADDLE_ENTERPRISE_PRICE_ID=""),
    )
    assert _plan_from_paddle_price("") is None


def test_unknown_lemonsqueezy_variant_is_not_entitled(monkeypatch):
    from backend.core.billing import _plan_from_ls_variant
    monkeypatch.setattr(
        "backend.core.config.settings",
        SimpleNamespace(LEMONSQUEEZY_STARTER_VARIANT_ID="", LEMONSQUEEZY_PRO_VARIANT_ID=""),
    )
    assert _plan_from_ls_variant("") is None
    assert _plan_from_ls_variant("unexpected-variant") is None


def paddle_settings(monkeypatch):
    monkeypatch.setattr(
        "backend.core.config.settings",
        SimpleNamespace(PADDLE_PRO_PRICE_ID="pro-id", PADDLE_ENTERPRISE_PRICE_ID="enterprise-id"),
    )


@pytest.mark.asyncio
async def test_paddle_canonical_active_subscription_grants_mapped_plan(monkeypatch):
    paddle_settings(monkeypatch)
    update = AsyncMock(return_value=True)
    monkeypatch.setattr("backend.core.billing.update_tenant_plan", update)
    result = await BillingService().handle_paddle_event(
        "subscription.created",
        {
            "custom_data": {"clerk_org_id": "org_1"},
            "customer_id": "cus_1",
            "status": "active",
            "items": [{"price": {"id": "pro-id"}}],
        },
    )
    assert result["status"] == "ok"
    assert result["plan"] == "pro"
    update.assert_awaited_once_with("org_1", "pro", "cus_1", "paddle")


@pytest.mark.asyncio
async def test_paddle_unknown_price_is_rejected_without_entitlement_update(monkeypatch):
    paddle_settings(monkeypatch)
    update = AsyncMock(return_value=True)
    monkeypatch.setattr("backend.core.billing.update_tenant_plan", update)
    result = await BillingService().handle_paddle_event(
        "subscription.updated",
        {
            "custom_data": {"clerk_org_id": "org_1"},
            "customer_id": "cus_1",
            "status": "active",
            "items": [{"price": {"id": "unknown-price"}}],
        },
    )
    assert result == {"status": "rejected", "reason": "unknown_price_id"}
    update.assert_not_awaited()


@pytest.mark.asyncio
async def test_paddle_ambiguous_multi_item_subscription_is_rejected(monkeypatch):
    paddle_settings(monkeypatch)
    update = AsyncMock(return_value=True)
    monkeypatch.setattr("backend.core.billing.update_tenant_plan", update)
    result = await BillingService().handle_paddle_event(
        "subscription.updated",
        {
            "custom_data": {"clerk_org_id": "org_1"},
            "customer_id": "cus_1",
            "status": "active",
            "items": [{"price": {"id": "pro-id"}}, {"price": {"id": "enterprise-id"}}],
        },
    )
    assert result == {"status": "rejected", "reason": "ambiguous_subscription_items"}
    update.assert_not_awaited()


@pytest.mark.asyncio
async def test_paddle_canceled_subscription_downgrades_to_free(monkeypatch):
    paddle_settings(monkeypatch)
    update = AsyncMock(return_value=True)
    monkeypatch.setattr("backend.core.billing.update_tenant_plan", update)
    result = await BillingService().handle_paddle_event(
        "subscription.canceled",
        {"custom_data": {"clerk_org_id": "org_1"}, "customer_id": "cus_1"},
    )
    assert result["status"] == "ok"
    assert result["plan"] == "free"
    update.assert_awaited_once_with("org_1", "free", "cus_1", "paddle")


def test_lemonsqueezy_event_key_is_stable_payload_digest():
    from backend.core.billing import derive_webhook_event_key

    payload = b'{"meta":{"event_name":"subscription_updated"}}'
    assert derive_webhook_event_key("lemonsqueezy", payload) == derive_webhook_event_key(
        "lemonsqueezy", payload
    )
    assert derive_webhook_event_key("lemonsqueezy", payload) != derive_webhook_event_key(
        "lemonsqueezy", payload + b" "
    )


def test_paddle_event_key_requires_provider_event_id():
    from backend.core.billing import derive_webhook_event_key

    assert derive_webhook_event_key("paddle", b"{}", None) is None
    assert derive_webhook_event_key("paddle", b"{}", "evt_test_1") == "evt_test_1"
    assert derive_webhook_event_key("unknown", b"{}", "evt_test_1") is None


def test_provider_timestamp_normalizes_to_utc():
    from datetime import timezone

    from backend.core.billing import parse_provider_timestamp

    parsed = parse_provider_timestamp("2026-10-10T12:30:00+02:00")
    assert parsed is not None
    assert parsed.tzinfo == timezone.utc
    assert parsed.isoformat() == "2026-10-10T10:30:00+00:00"
    assert parse_provider_timestamp("not-a-date") is None


class _FakeTransaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False


class _FakeBillingSession:
    def __init__(self, results):
        self._results = list(results)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    def begin(self):
        return _FakeTransaction()

    async def execute(self, statement):
        return self._results.pop(0)


class _FakeScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


@pytest.mark.asyncio
async def test_paddle_webhook_duplicate_is_not_applied_twice(monkeypatch):
    import hashlib
    from types import SimpleNamespace

    from backend.core.billing import BillingService

    payload = b'{"event_id":"evt_test_1","event_type":"subscription.created"}'
    digest = hashlib.sha256(payload).hexdigest()
    existing = SimpleNamespace(
        payload_sha256=digest,
        status="processed",
        event_type="subscription.created",
    )
    fake_session = _FakeBillingSession(
        [_FakeScalarResult(None), _FakeScalarResult(existing)]
    )
    monkeypatch.setattr(
        "backend.models.database.AsyncSessionFactory",
        lambda: fake_session,
    )
    update = AsyncMock()
    monkeypatch.setattr("backend.core.billing.update_tenant_plan", update)

    result = await BillingService().process_webhook_event(
        "paddle",
        "evt_test_1",
        payload,
        "subscription.created",
        {"custom_data": {"clerk_org_id": "org_1"}},
        None,
        "sub_1",
    )

    assert result == {"status": "duplicate", "event": "subscription.created"}
    update.assert_not_awaited()


@pytest.mark.asyncio
async def test_paddle_webhook_stale_subscription_snapshot_is_ignored(monkeypatch):
    import hashlib
    import uuid
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace

    from backend.core.billing import BillingService

    payload = b'{"event_id":"evt_older","event_type":"subscription.updated"}'
    digest = hashlib.sha256(payload).hexdigest()
    occurred_at = datetime(2026, 10, 10, 10, 0, tzinfo=timezone.utc)
    current_event = SimpleNamespace(
        status="processing",
        payload_sha256=digest,
        occurred_at=occurred_at,
        processed_at=None,
        result={},
    )
    tenant = SimpleNamespace(clerk_org_id="org_1")
    newer_event = SimpleNamespace(occurred_at=occurred_at + timedelta(seconds=1))
    fake_session = _FakeBillingSession(
        [
            _FakeScalarResult(uuid.uuid4()),
            _FakeScalarResult(current_event),
            _FakeScalarResult(tenant),
            _FakeScalarResult(newer_event),
        ]
    )
    monkeypatch.setattr(
        "backend.models.database.AsyncSessionFactory",
        lambda: fake_session,
    )
    update = AsyncMock()
    monkeypatch.setattr("backend.core.billing.update_tenant_plan", update)

    result = await BillingService().process_webhook_event(
        "paddle",
        "evt_older",
        payload,
        "subscription.updated",
        {
            "custom_data": {"clerk_org_id": "org_1"},
            "customer_id": "cus_1",
            "status": "active",
            "items": [{"price": {"id": "pro-id"}}],
        },
        occurred_at,
        "sub_1",
    )

    assert result == {"status": "stale", "event": "subscription.updated"}
    assert current_event.status == "stale"
    update.assert_not_awaited()
