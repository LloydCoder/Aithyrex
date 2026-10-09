"""
AI Shield — Unit Tests: NIS2/DORA Compliance Hooks
====================================================
Tests KalevioAI notification logic and threshold detection.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from backend.compliance.nis2_dora import NIS2DoraHooks
from backend.core.shield_engine import (
    Action, DetectionResult, Severity, ShieldVerdict
)


@pytest.fixture
def hooks():
    return NIS2DoraHooks()


@pytest.fixture
def critical_verdict():
    return ShieldVerdict(
        action=Action.BLOCK,
        severity=Severity.CRITICAL,
        blocked=True,
        results=[
            DetectionResult(
                detector="credential_leak",
                detected=True,
                severity=Severity.CRITICAL,
                confidence=0.99,
                mitre_atlas=["T1552"],
            )
        ],
    )


@pytest.fixture
def high_verdict():
    return ShieldVerdict(
        action=Action.ALERT,
        severity=Severity.HIGH,
        blocked=False,
        results=[
            DetectionResult(
                detector="prompt_injection",
                detected=True,
                severity=Severity.HIGH,
                confidence=0.85,
                mitre_atlas=["AML.T0051"],
            )
        ],
    )


# ── Free plan — no notifications ─────────────────────────────────────────────
@pytest.mark.asyncio
async def test_free_plan_no_notification(hooks, critical_verdict):
    """Free plan should never trigger KalevioAI — even for CRITICAL."""
    with patch.object(hooks, "_notify_kalevio", new=AsyncMock()) as mock_notify:
        await hooks.evaluate(critical_verdict, "tenant-free", plan="free")
        mock_notify.assert_not_called()


@pytest.mark.asyncio
async def test_starter_plan_no_notification(hooks, critical_verdict):
    """Starter plan: no compliance reports."""
    with patch.object(hooks, "_notify_kalevio", new=AsyncMock()) as mock_notify:
        await hooks.evaluate(critical_verdict, "tenant-starter", plan="starter")
        mock_notify.assert_not_called()


# ── Enterprise plan — notifications fire ─────────────────────────────────────
@pytest.mark.asyncio
async def test_enterprise_critical_notifies_immediately(hooks, critical_verdict):
    """Enterprise CRITICAL → immediate KalevioAI notification."""
    with patch.object(hooks, "_notify_kalevio", new=AsyncMock()) as mock_notify:
        await hooks.evaluate(critical_verdict, "tenant-ent", plan="enterprise")
        mock_notify.assert_called_once()
        call_kwargs = mock_notify.call_args.kwargs
        assert call_kwargs["urgency"] == "critical"


@pytest.mark.asyncio
async def test_enterprise_3_highs_triggers_cluster_alert(hooks, high_verdict):
    """3 HIGH events in < 1 hour → cluster alert."""
    with patch.object(hooks, "_notify_kalevio", new=AsyncMock()) as mock_notify:
        await hooks.evaluate(high_verdict, "tenant-ent", plan="enterprise")
        await hooks.evaluate(high_verdict, "tenant-ent", plan="enterprise")
        assert mock_notify.call_count == 0   # 2 highs — not yet

        await hooks.evaluate(high_verdict, "tenant-ent", plan="enterprise")
        assert mock_notify.call_count == 1   # 3rd high fires it
        call_kwargs = mock_notify.call_args.kwargs
        assert call_kwargs["urgency"] == "high_cluster"


@pytest.mark.asyncio
async def test_high_counter_resets_after_cluster_alert(hooks, high_verdict):
    """After cluster alert fires, counter resets — not double-fired."""
    with patch.object(hooks, "_notify_kalevio", new=AsyncMock()) as mock_notify:
        for _ in range(3):
            await hooks.evaluate(high_verdict, "tenant-ent", plan="enterprise")
        assert mock_notify.call_count == 1

        # Two more highs — not enough for new cluster
        await hooks.evaluate(high_verdict, "tenant-ent", plan="enterprise")
        await hooks.evaluate(high_verdict, "tenant-ent", plan="enterprise")
        assert mock_notify.call_count == 1   # still 1, counter reset


# ── Payload correctness ───────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_kalevio_payload_structure(hooks, critical_verdict):
    """KalevioAI payload must include all required NIS2 fields."""
    import httpx

    captured = {}

    async def mock_post(url, **kwargs):
        captured.update(kwargs.get("json", {}))
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    with patch("backend.core.config.settings") as mock_settings:
        mock_settings.KALEVIOAI_API_URL = "https://api.kalevioai.com"
        mock_settings.KALEVIOAI_API_KEY = "test-key"

        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=mock_post
            )
            await hooks._notify_kalevio(critical_verdict, "tenant-ent", "critical")

    assert captured.get("source") == "ai_shield"
    assert captured.get("severity") == "critical"
    assert captured.get("requires_nis2_report") is True
    assert "detectors_fired" in captured
    assert "mitre_atlas" in captured
    assert "timestamp" in captured
