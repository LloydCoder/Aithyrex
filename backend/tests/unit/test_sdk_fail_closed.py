from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ai_shield.client import Shield
from aithyrex import AithyrexClient


@pytest.mark.asyncio
async def test_missing_api_url_fails_closed():
    verdict = await Shield(token="signed-session-token", base_url="").inspect("hello")
    assert verdict.blocked is True
    assert verdict.degraded is True
    assert verdict.error_code == "api_url_not_configured"


@pytest.mark.asyncio
async def test_missing_session_token_fails_closed():
    verdict = await Shield(base_url="https://api.example.test").inspect("hello")
    assert verdict.blocked is True
    assert verdict.error_code == "session_token_not_configured"


@pytest.mark.asyncio
async def test_transport_failure_fails_closed():
    import httpx

    context = MagicMock()
    context.__aenter__ = AsyncMock(side_effect=httpx.ConnectError("unreachable"))
    context.__aexit__ = AsyncMock(return_value=False)
    with patch("httpx.AsyncClient", return_value=context):
        verdict = await Shield(token="signed-session-token", base_url="https://api.example.test").inspect("hello")
    assert verdict.blocked is True
    assert verdict.degraded is True
    assert verdict.error_code == "inspection_unreachable"


@pytest.mark.asyncio
async def test_malformed_api_response_fails_closed():
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json.return_value = {"action": "pass", "severity": "clean", "detections": []}
    client = MagicMock()
    client.post = AsyncMock(return_value=response)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=client)
    context.__aexit__ = AsyncMock(return_value=False)
    with patch("httpx.AsyncClient", return_value=context):
        verdict = await Shield(token="signed-session-token", base_url="https://api.example.test").inspect("hello")
    assert verdict.blocked is True
    assert verdict.error_code == "invalid_response_schema"


def test_canonical_import_namespace_exports_client():
    assert AithyrexClient is Shield


@pytest.mark.asyncio
async def test_successful_inspection_propagates_and_validates_request_id():
    from uuid import UUID

    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.headers = {}
    response.json.return_value = {
        "action": "pass",
        "severity": "clean",
        "blocked": False,
        "detections": [],
        "tenant_id": "tenant-test",
    }
    client = MagicMock()
    client.post = AsyncMock(return_value=response)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=client)
    context.__aexit__ = AsyncMock(return_value=False)

    with patch("httpx.AsyncClient", return_value=context):
        verdict = await Shield(
            token="signed-session-token", base_url="https://api.example.test"
        ).inspect("hello")

    request_kwargs = client.post.await_args.kwargs
    request_id = request_kwargs["headers"]["X-Request-ID"]
    UUID(request_id)
    assert verdict.trace_id == request_id
    assert verdict.blocked is False


@pytest.mark.asyncio
async def test_trace_id_mismatch_fails_closed():
    from uuid import uuid4

    request_id = str(uuid4())
    response_id = str(uuid4())
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.headers = {"X-Request-ID": request_id}
    response.json.return_value = {
        "action": "pass",
        "severity": "clean",
        "blocked": False,
        "detections": [],
        "trace_id": response_id,
        "tenant_id": "tenant-test",
    }
    client = MagicMock()
    client.post = AsyncMock(return_value=response)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=client)
    context.__aexit__ = AsyncMock(return_value=False)

    with patch("httpx.AsyncClient", return_value=context):
        verdict = await Shield(
            token="signed-session-token", base_url="https://api.example.test"
        ).inspect("hello")

    assert verdict.blocked is True
    assert verdict.degraded is True
    assert verdict.error_code == "trace_id_mismatch"
