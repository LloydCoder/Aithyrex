import hashlib
import hmac
import time

import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock

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
    result = __import__("asyncio").run(BillingService().handle_paddle_event(
        "subscription.updated",
        {
            "custom_data": {"clerk_org_id": "org_1"},
            "customer_id": "cus_1",
            "status": "active",
            "items": [{"price": {"id": "unknown-price"}}],
        },
    ))
    assert result == {"status": "rejected", "reason": "unknown_price_id"}
    update.assert_not_awaited()


@pytest.mark.asyncio
async def test_paddle_ambiguous_multi_item_subscription_is_rejected(monkeypatch):
    paddle_settings(monkeypatch)
    update = AsyncMock(return_value=True)
    monkeypatch.setattr("backend.core.billing.update_tenant_plan", update)
    result = __import__("asyncio").run(BillingService().handle_paddle_event(
        "subscription.updated",
        {
            "custom_data": {"clerk_org_id": "org_1"},
            "customer_id": "cus_1",
            "status": "active",
            "items": [{"price": {"id": "pro-id"}}, {"price": {"id": "enterprise-id"}}],
        },
    ))
    assert result == {"status": "rejected", "reason": "ambiguous_subscription_items"}
    update.assert_not_awaited()


@pytest.mark.asyncio
async def test_paddle_canceled_subscription_downgrades_to_free(monkeypatch):
    paddle_settings(monkeypatch)
    update = AsyncMock(return_value=True)
    monkeypatch.setattr("backend.core.billing.update_tenant_plan", update)
    result = __import__("asyncio").run(BillingService().handle_paddle_event(
        "subscription.canceled",
        {"custom_data": {"clerk_org_id": "org_1"}, "customer_id": "cus_1"},
    ))
    assert result["status"] == "ok"
    assert result["plan"] == "free"
    update.assert_awaited_once_with("org_1", "free", "cus_1", "paddle")
