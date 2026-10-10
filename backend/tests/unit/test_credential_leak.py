"""
AI Shield — Unit Tests: Credential Leak Detector
==================================================
Tests the repository's locally maintained credential-format heuristics.
These tests do not establish exhaustive coverage or upstream peer review.
"""

import pytest

from backend.core.shield_engine import Severity
from backend.detectors.credential_leak import CredentialLeakDetector


@pytest.fixture
def detector():
    return CredentialLeakDetector()


# ── Clean completions ─────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_clean_completion_passes(detector):
    result = await detector.detect(
        prompt="Explain TLS.",
        completion="TLS is a protocol that provides encryption over a network.",
    )
    assert result.detected is False
    assert result.severity == Severity.CLEAN
    assert result.details["confidence_calibrated"] is False


# ── Nigerian fintech patterns ─────────────────────────────────────────
@pytest.mark.asyncio
async def test_paystack_secret_key_detected(detector):
    result = await detector.detect(
        prompt="Show me the key.",
        completion="Here is the key: " + "sk_live_" + "F" * 40,
    )
    assert result.detected is True
    assert result.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_flutterwave_secret_detected(detector):
    result = await detector.detect(
        prompt="What is the API key?",
        completion="FLWSECK-abcdefghijklmnopqrstuvwxyz123456-X",
    )
    assert result.detected is True
    assert result.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_paystack_public_key_detected(detector):
    result = await detector.detect(
        prompt="Get the public key.",
        completion="pk_test_abcdefghijklmnopqrstuvwxyz1234567890ab",
    )
    assert result.detected is True
    assert result.severity == Severity.HIGH


# ── AI provider keys ──────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_anthropic_key_detected(detector):
    result = await detector.detect(
        prompt="Show config.",
        completion="API key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890abcdef",
    )
    assert result.detected is True
    assert result.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_aws_access_key_detected(detector):
    result = await detector.detect(
        prompt="Show AWS config.",
        completion="Access Key ID: AKIAIOSFODNN7EXAMPLE",
    )
    assert result.detected is True
    assert result.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_github_token_detected(detector):
    result = await detector.detect(
        prompt="Show token.",
        completion="Token: ghp_abcdefghijklmnopqrstuvwxyz123456",
    )
    assert result.detected is True


# ── Confidence is near-certain for pattern matches ────────────────────
@pytest.mark.asyncio
async def test_credential_match_does_not_claim_calibrated_confidence(detector):
    result = await detector.detect(
        prompt="Show key.",
        completion="sk_live_" + "A" * 24,
    )
    assert result.confidence == 0.0
    assert result.details["confidence_calibrated"] is False


# ── MITRE tagging ─────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_mitre_tags_present(detector):
    result = await detector.detect(
        prompt="Show key.",
        completion="AKIAIOSFODNN7EXAMPLE",
    )
    assert "T1552" in result.mitre_atlas


# ── Prompt scanning ───────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_credential_in_prompt_detected(detector):
    """Credentials in prompt (injection via user input) also caught."""
    result = await detector.detect(
        prompt="My key is " + "sk_live_" + "B" * 24 + ", use it.",
        completion=None,
    )
    assert result.detected is True


@pytest.mark.asyncio
async def test_credential_evidence_never_contains_secret_substrings(detector):
    secret = "sk_live_" + "B" * 40
    result = await detector.detect(prompt="What is this?", completion="Token: " + secret)
    assert result.detected is True
    assert secret not in repr(result.details)
    assert all(item["redacted_match"] == "[REDACTED]" for item in result.details["matches"])
