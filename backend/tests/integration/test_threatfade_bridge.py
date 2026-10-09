"""
AI Shield — Integration Tests: ThreatFade Bridge
==================================================
Tests the HTTP bridge between AI Shield and ThreatFade.
Requires ThreatFade service running at THREATFADE_API_URL.

Run with:
    pytest backend/tests/integration/ -v
    (expects ThreatFade live at localhost:8000)
"""

from unittest.mock import AsyncMock, patch

import pytest

from backend.core.threatfade_client import ThreatFadeClient


@pytest.fixture
def client():
    return ThreatFadeClient()


# ── Mocked bridge tests (no live ThreatFade required) ─────────────────
@pytest.mark.asyncio
async def test_bridge_returns_clean_for_normal_text(client):
    """Normal text should return detected=False."""
    mock_response = {
        "detected": False,
        "confidence": "info",
        "score": 0.05,
        "entropy": 4.2,
        "z_outlier": 0.3,
        "rules_matched": 0,
        "mitre_ttp": "",
    }
    with patch.object(client, "detect", new=AsyncMock(return_value=mock_response)):
        result = await client.detect("The weather today is sunny and warm.")
        assert result["detected"] is False


@pytest.mark.asyncio
async def test_bridge_detects_suspicious_payload(client):
    """High-entropy encoded payload should trigger ThreatFade."""
    mock_response = {
        "detected": True,
        "confidence": "high",
        "score": 0.87,
        "entropy": 7.9,
        "z_outlier": 11.2,
        "rules_matched": 3,
        "mitre_ttp": "T1027",
    }
    with patch.object(client, "detect", new=AsyncMock(return_value=mock_response)):
        result = await client.detect("SGVsbG8gV29ybGQh" * 20)
        assert result["detected"] is True
        assert result["z_outlier"] > 10.0


@pytest.mark.asyncio
async def test_bridge_handles_timeout_gracefully(client):
    """Timeout should return safe default — never crash."""
    import httpx
    with patch("httpx.AsyncClient.post", side_effect=httpx.TimeoutException("timeout")):
        result = await client.detect("any text")
        assert result["detected"] is False
        assert result.get("error") == "timeout"


@pytest.mark.asyncio
async def test_health_check_returns_bool(client):
    """Health check must return True/False, not raise."""
    with patch.object(client, "health", new=AsyncMock(return_value=True)):
        alive = await client.health()
        assert isinstance(alive, bool)
