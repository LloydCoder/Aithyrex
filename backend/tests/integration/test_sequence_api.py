"""API contract tests for signed behavioral sequence analysis."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from backend.core.config import settings
from backend.core.platform_sequence_auth import sequence_sha256


def _payload():
    start = datetime.now(timezone.utc).replace(microsecond=0)
    return {
        "agent_id": "agent-42",
        "sequence_id": "sequence-integration-1",
        "events": [
            {
                "event_id": "evt-injection",
                "event_type": "prompt_injection_detected",
                "occurred_at": start.isoformat(),
                "signals": ["prompt_injection_rule"],
            },
            {
                "event_id": "evt-transfer",
                "event_type": "external_transfer_requested",
                "occurred_at": (start + timedelta(seconds=90)).isoformat(),
                "signals": ["external_transfer"],
            },
        ],
    }


def _signed_assertion(monkeypatch, payload):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    issuer, audience = "https://agent-platform.tinlance.internal", "aithyrex"
    monkeypatch.setattr(settings, "PLATFORM_ACTION_JWT_PUBLIC_KEY", public_pem)
    monkeypatch.setattr(settings, "PLATFORM_ACTION_JWT_ISSUER", issuer)
    monkeypatch.setattr(settings, "PLATFORM_ACTION_JWT_AUDIENCE", audience)
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": payload["agent_id"],
        "jti": "sequence-integration-event-1",
        "tenant_id": "00000000-0000-4000-8000-000000000001",
        "sequence_id": payload["sequence_id"],
        "sequence_sha256": sequence_sha256(payload["agent_id"], payload["sequence_id"], payload["events"]),
        "iat": int(time.time()),
        "exp": int(time.time()) + 120,
    }
    return jwt.encode(claims, private_pem, algorithm="RS256")


def test_sequence_endpoint_requires_platform_assertion(client: TestClient):
    response = client.post("/api/v1/detect/sequence", json=_payload())
    assert response.status_code == 401
    assert response.json()["error_code"] == "missing_platform_sequence_assertion"


def test_signed_sequence_returns_advisory_correlation(client: TestClient, monkeypatch):
    payload = _payload()
    assertion = _signed_assertion(monkeypatch, payload)
    response = client.post(
        "/api/v1/detect/sequence",
        json=payload,
        headers={"X-Platform-Sequence-Assertion": assertion},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema_version"] == "aithyrex.behavioral-correlation.v1"
    assert body["detected"] is True
    assert body["severity"] == "high"
    assert body["findings"][0]["rule_id"] == "injection_then_external_action"
    assert body["advisory_only"] is True
    assert body["authorization_performed"] is False
    assert body["execution_performed"] is False
    assert body["finding"]["blocked"] is False


def test_sequence_tampering_is_rejected(client: TestClient, monkeypatch):
    payload = _payload()
    assertion = _signed_assertion(monkeypatch, payload)
    payload["events"][1]["event_type"] = "tool_action_proposed"
    response = client.post(
        "/api/v1/detect/sequence",
        json=payload,
        headers={"X-Platform-Sequence-Assertion": assertion},
    )
    assert response.status_code == 403
    assert response.json()["error_code"] == "platform_sequence_binding_mismatch"


def test_isolated_injection_signal_does_not_create_sequence_finding(client: TestClient, monkeypatch):
    payload = _payload()
    payload["events"] = payload["events"][:1] + [
        {
            "event_id": "evt-unrelated",
            "event_type": "approval_recorded",
            "occurred_at": (datetime.fromisoformat(payload["events"][0]["occurred_at"]) + timedelta(seconds=90)).isoformat(),
        }
    ]
    assertion = _signed_assertion(monkeypatch, payload)
    response = client.post(
        "/api/v1/detect/sequence",
        json=payload,
        headers={"X-Platform-Sequence-Assertion": assertion},
    )
    assert response.status_code == 200, response.text
    assert response.json()["detected"] is False
    assert response.json()["findings"] == []

def test_out_of_order_sequence_is_rejected(client: TestClient):
    payload = _payload()
    payload["events"].reverse()
    response = client.post("/api/v1/detect/sequence", json=payload)
    assert response.status_code == 422
    assert "ordered" in response.text.lower()
