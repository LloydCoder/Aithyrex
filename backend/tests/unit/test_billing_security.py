import hashlib
import hmac
import time
from types import SimpleNamespace

import pytest

from backend.core.billing import verify_lemonsqueezy_signature, verify_paddle_signature, _plan_from_paddle_price


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
    assert _plan_from_paddle_price("unexpected-price") == "free"
