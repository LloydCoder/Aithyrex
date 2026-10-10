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


@pytest.mark.asyncio
async def test_transient_http_failure_retries_once_then_succeeds():
    import httpx

    payload = {"detected": False, "z_outlier": 0.2, "confidence": "info"}
    request = httpx.Request("POST", "https://threatfade.test/detect/json")
    responses = [
        httpx.Response(503, request=request),
        httpx.Response(200, json=payload, request=request),
    ]
    context = fake_http_context(payload)
    fake_client = context.__aenter__.return_value
    fake_client.post.side_effect = responses
    with patch("backend.core.threatfade_client.httpx.AsyncClient", return_value=context), patch(
        "backend.core.threatfade_client.asyncio.sleep", new=AsyncMock()
    ):
        result = await ThreatFadeClient().detect("test text")
    assert result["degraded"] is False
    assert fake_client.post.await_count == 2


@pytest.mark.asyncio
async def test_non_retryable_http_failure_is_not_retried():
    import httpx

    request = httpx.Request("POST", "https://threatfade.test/detect/json")
    response = httpx.Response(401, request=request)
    context = fake_http_context({})
    context.__aenter__.return_value.post.return_value = response
    with patch("backend.core.threatfade_client.httpx.AsyncClient", return_value=context):
        result = await ThreatFadeClient().detect("test text")
    assert result["degraded"] is True
    assert result["error"] == "http_status_error"
    assert context.__aenter__.return_value.post.await_count == 1


@pytest.mark.asyncio
async def test_invalid_confidence_is_degraded():
    context = fake_http_context({"detected": True, "z_outlier": 4.2, "confidence": "certain"})
    with patch("backend.core.threatfade_client.httpx.AsyncClient", return_value=context):
        result = await ThreatFadeClient().detect("test text")
    assert result["degraded"] is True
    assert result["error"] == "invalid_confidence"


@pytest.mark.asyncio
async def test_upstream_fallback_is_not_reported_as_available():
    context = fake_http_context({"detected": False, "z_outlier": 0.2, "fallback": True})
    with patch("backend.core.threatfade_client.httpx.AsyncClient", return_value=context):
        result = await ThreatFadeClient().detect("test text")
    assert result["degraded"] is True
    assert result["available"] is False
    assert result["error"] == "degraded_upstream_response"


@pytest.mark.asyncio
async def test_oversized_text_is_rejected_without_network_call():
    context = fake_http_context({"detected": False, "z_outlier": 0.2})
    with patch("backend.core.threatfade_client.httpx.AsyncClient", return_value=context):
        result = await ThreatFadeClient().detect("x" * 200_001)
    assert result["degraded"] is True
    assert result["error"] == "invalid_or_oversized_input"
    context.__aenter__.return_value.post.assert_not_awaited()


@pytest.mark.asyncio
async def test_malformed_availability_marker_is_degraded():
    context = fake_http_context({"detected": False, "z_outlier": 0.2, "available": "false"})
    with patch("backend.core.threatfade_client.httpx.AsyncClient", return_value=context):
        result = await ThreatFadeClient().detect("test text")
    assert result["degraded"] is True
    assert result["available"] is False
    assert result["error"] == "invalid_available"
