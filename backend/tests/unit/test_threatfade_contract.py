from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.core.threatfade_client import ThreatFadeClient


def fake_http_context(payload):
    response = MagicMock()
    response.json.return_value = payload
    response.raise_for_status = MagicMock()
    client = MagicMock()
    client.post = AsyncMock(return_value=response)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=client)
    context.__aexit__ = AsyncMock(return_value=False)
    return context


@pytest.mark.asyncio
async def test_missing_threatfade_z_score_is_degraded():
    context = fake_http_context({"detected": False, "confidence": "info"})
    with patch("backend.core.threatfade_client.httpx.AsyncClient", return_value=context):
        result = await ThreatFadeClient().detect("test text")
    assert result["degraded"] is True
    assert result["available"] is False
    assert result["error"] == "invalid_response_schema"


@pytest.mark.asyncio
async def test_non_finite_threatfade_z_score_is_degraded():
    context = fake_http_context({"detected": False, "z_outlier": float("nan")})
    with patch("backend.core.threatfade_client.httpx.AsyncClient", return_value=context):
        result = await ThreatFadeClient().detect("test text")
    assert result["degraded"] is True
    assert result["error"] == "invalid_z_outlier"


@pytest.mark.asyncio
async def test_valid_threatfade_response_is_not_degraded():
    context = fake_http_context({"detected": False, "z_outlier": 0.2})
    with patch("backend.core.threatfade_client.httpx.AsyncClient", return_value=context):
        result = await ThreatFadeClient().detect("test text")
    assert result["degraded"] is False
    assert result["available"] is True
    assert result["z_outlier"] == 0.2
