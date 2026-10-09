import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from backend.core.auth import _verify_clerk_token, get_current_tenant, get_optional_tenant


@pytest.mark.asyncio
async def test_missing_clerk_jwt_trust_anchors_fail_closed(monkeypatch):
    monkeypatch.setattr(
        "backend.core.auth._get_settings",
        lambda: SimpleNamespace(CLERK_JWT_KEY="", CLERK_JWT_ISSUER="", CLERK_AUTHORIZED_PARTIES=[]),
    )
    assert await _verify_clerk_token("arbitrary-token") == {}


@pytest.mark.asyncio
async def test_missing_credentials_returns_401():
    with pytest.raises(HTTPException) as exc:
        await get_current_tenant(None)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_personal_session_without_active_org_is_denied(monkeypatch):
    monkeypatch.setattr(
        "backend.core.auth._verify_clerk_token",
        AsyncMock(return_value={"sub": "user_123"}),
    )
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="signed-token")
    with pytest.raises(HTTPException) as exc:
        await get_current_tenant(credentials)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_plan_claim_is_ignored_in_favor_of_server_side_entitlement(monkeypatch):
    tenant = SimpleNamespace(
        id=uuid.UUID("00000000-0000-4000-8000-000000000002"),
        plan="enterprise",
        is_active=True,
    )
    session = MagicMock()
    query_result = MagicMock()
    query_result.scalar_one_or_none.return_value = tenant
    session.execute = AsyncMock(return_value=query_result)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=session)
    context.__aexit__ = AsyncMock(return_value=False)
    monkeypatch.setattr(
        "backend.core.auth._verify_clerk_token",
        AsyncMock(return_value={
            "sub": "user_123",
            "org_id": "org_123",
            "public_metadata": {"plan": "free"},
        }),
    )
    with patch("backend.models.database.AsyncSessionFactory", return_value=context):
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="signed-token")
        result = await get_current_tenant(credentials)
    assert result.tenant_id == "00000000-0000-4000-8000-000000000002"
    assert result.plan == "enterprise"


@pytest.mark.asyncio
async def test_optional_auth_does_not_downgrade_invalid_token_to_anonymous(monkeypatch):
    monkeypatch.setattr(
        "backend.core.auth._verify_clerk_token",
        AsyncMock(return_value={}),
    )
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid-token")
    with pytest.raises(HTTPException) as exc:
        await get_optional_tenant(credentials)
    assert exc.value.status_code == 401
