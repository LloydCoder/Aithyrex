"""Tests for signed Platform action assertions; keys are generated per test run."""

from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from backend.core.config import settings
from backend.core.platform_action_auth import action_payload_sha256, decode_platform_action_assertion


@pytest.fixture
def signing_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def _claims(**overrides):
    now = int(time.time())
    claims = {
        "iss": "https://agent-platform.tinlance.internal",
        "aud": "aithyrex",
        "sub": "agent-42",
        "jti": "event-123",
        "tenant_id": "00000000-0000-4000-8000-000000000001",
        "action_id": "action-123",
        "tool_name": "send_email",
        "action_payload_sha256": "a" * 64,
        "iat": now,
        "exp": now + 120,
    }
    claims.update(overrides)
    return claims


def _configure(monkeypatch, public_key: str):
    monkeypatch.setattr(settings, "PLATFORM_ACTION_JWT_PUBLIC_KEY", public_key)
    monkeypatch.setattr(settings, "PLATFORM_ACTION_JWT_ISSUER", "https://agent-platform.tinlance.internal")
    monkeypatch.setattr(settings, "PLATFORM_ACTION_JWT_AUDIENCE", "aithyrex")


def test_valid_rs256_assertion_is_verified(monkeypatch, signing_keys):
    private_key, public_key = signing_keys
    _configure(monkeypatch, public_key)
    token = jwt.encode(_claims(), private_key, algorithm="RS256")

    claims = decode_platform_action_assertion(token)

    assert claims["sub"] == "agent-42"
    assert claims["tenant_id"] == "00000000-0000-4000-8000-000000000001"
    assert claims["jti"] == "event-123"


def test_missing_trust_configuration_fails_closed(monkeypatch):
    monkeypatch.setattr(settings, "PLATFORM_ACTION_JWT_PUBLIC_KEY", "")
    monkeypatch.setattr(settings, "PLATFORM_ACTION_JWT_ISSUER", "")
    monkeypatch.setattr(settings, "PLATFORM_ACTION_JWT_AUDIENCE", "")

    with pytest.raises(HTTPException) as error:
        decode_platform_action_assertion("not-a-token")

    assert error.value.status_code == 503


def test_malformed_public_key_fails_as_configuration_error(monkeypatch, signing_keys):
    private_key, _public_key = signing_keys
    monkeypatch.setattr(settings, "PLATFORM_ACTION_JWT_PUBLIC_KEY", "not-a-public-key")
    monkeypatch.setattr(settings, "PLATFORM_ACTION_JWT_ISSUER", "https://agent-platform.tinlance.internal")
    monkeypatch.setattr(settings, "PLATFORM_ACTION_JWT_AUDIENCE", "aithyrex")
    token = jwt.encode(_claims(), private_key, algorithm="RS256")

    with pytest.raises(HTTPException) as error:
        decode_platform_action_assertion(token)

    assert error.value.status_code == 503


def test_invalid_signature_is_rejected(monkeypatch, signing_keys):
    private_key, _public_key = signing_keys
    other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_public = other_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    _configure(monkeypatch, other_public)
    token = jwt.encode(_claims(), private_key, algorithm="RS256")

    with pytest.raises(HTTPException) as error:
        decode_platform_action_assertion(token)

    assert error.value.status_code == 401


def test_expired_assertion_is_rejected(monkeypatch, signing_keys):
    private_key, public_key = signing_keys
    _configure(monkeypatch, public_key)
    token = jwt.encode(_claims(exp=int(time.time()) - 30), private_key, algorithm="RS256")

    with pytest.raises(HTTPException) as error:
        decode_platform_action_assertion(token)

    assert error.value.status_code == 401


def test_assertion_lifetime_is_bounded(monkeypatch, signing_keys):
    private_key, public_key = signing_keys
    _configure(monkeypatch, public_key)
    now = int(time.time())
    token = jwt.encode(_claims(iat=now, exp=now + 3_600), private_key, algorithm="RS256")

    with pytest.raises(HTTPException) as error:
        decode_platform_action_assertion(token)

    assert error.value.status_code == 401


def test_malformed_payload_hash_is_rejected(monkeypatch, signing_keys):
    private_key, public_key = signing_keys
    _configure(monkeypatch, public_key)
    token = jwt.encode(_claims(action_payload_sha256="not-a-hash"), private_key, algorithm="RS256")

    with pytest.raises(HTTPException) as error:
        decode_platform_action_assertion(token)

    assert error.value.status_code == 401


def test_action_payload_hash_is_deterministic_and_content_bound():
    first = action_payload_sha256("send_email", {"to": "user@example.com", "subject": "Hello"}, "review draft")
    reordered = action_payload_sha256("send_email", {"subject": "Hello", "to": "user@example.com"}, "review draft")
    changed = action_payload_sha256("send_email", {"to": "attacker@example.com", "subject": "Hello"}, "review draft")

    assert first == reordered
    assert first != changed
