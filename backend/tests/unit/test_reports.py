import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

from fastapi import HTTPException
import pytest

from backend.api.routes.reports import (
    _export_evidence,
    export_compliance_evidence,
    trigger_compliance_report,
)
from backend.core.auth import TokenPayload


EVENT_ID = "00000000-0000-4000-8000-000000000001"
TENANT_ID = "00000000-0000-4000-8000-000000000002"


def make_event():
    return SimpleNamespace(
        id=UUID(EVENT_ID),
        tenant_id=UUID(TENANT_ID),
        created_at=datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc),
        model="gpt-4o",
        prompt_len=10,
        completion_len=5,
        action="block",
        severity="critical",
        blocked=True,
        results=[{
            "detector": "credential_leak", "detected": True,
            "severity": "critical", "confidence": 0.9,
            "mitre_atlas": ["T1552"], "details": {"secret": "not-exported"},
        }],
    )


def fake_session_context(event=None, *, error=None):
    session = MagicMock()
    if error is not None:
        session.execute = AsyncMock(side_effect=error)
    else:
        result = MagicMock()
        result.scalar_one_or_none.return_value = event
        session.execute = AsyncMock(return_value=result)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=session)
    context.__aexit__ = AsyncMock(return_value=False)
    return context, session


@pytest.mark.asyncio
async def test_non_enterprise_cannot_export_and_database_is_not_touched():
    tenant = TokenPayload(TENANT_ID, "user", plan="pro")
    with patch("backend.models.database.AsyncSessionFactory") as factory:
        with pytest.raises(HTTPException) as exc:
            await _export_evidence(EVENT_ID, "json", tenant)
    assert exc.value.status_code == 403
    factory.assert_not_called()


@pytest.mark.asyncio
async def test_cross_tenant_or_missing_event_returns_same_404():
    tenant = TokenPayload(TENANT_ID, "user", plan="enterprise")
    context, session = fake_session_context(event=None)
    with patch("backend.models.database.AsyncSessionFactory", return_value=context):
        with pytest.raises(HTTPException) as exc:
            await _export_evidence(EVENT_ID, "json", tenant)
    assert exc.value.status_code == 404
    statement = session.execute.await_args.args[0]
    sql = str(statement)
    assert "detection_events.tenant_id" in sql
    assert "detection_events.id" in sql


@pytest.mark.asyncio
async def test_json_export_returns_digest_header_and_no_store():
    tenant = TokenPayload(TENANT_ID, "user", plan="enterprise")
    context, _ = fake_session_context(event=make_event())
    with patch("backend.models.database.AsyncSessionFactory", return_value=context):
        response = await export_compliance_evidence(EVENT_ID, tenant, "json")
    envelope = json.loads(response.body)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-aithyrex-evidence-digest"] == envelope["evidence_digest"]
    assert envelope["submission"]["status"] == "not_submitted"
    assert "not-exported" not in response.body.decode()


@pytest.mark.asyncio
async def test_csv_and_markdown_formats_are_supported():
    tenant = TokenPayload(TENANT_ID, "user", plan="enterprise")
    for export_format, media_type, extension in (
        ("csv", "text/csv", ".csv"),
        ("markdown", "text/markdown", ".md"),
    ):
        context, _ = fake_session_context(event=make_event())
        with patch("backend.models.database.AsyncSessionFactory", return_value=context):
            response = await trigger_compliance_report(EVENT_ID, tenant, export_format)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(media_type)
        assert extension in response.headers["content-disposition"]


@pytest.mark.asyncio
async def test_invalid_event_uuid_returns_404_without_database_access():
    tenant = TokenPayload(TENANT_ID, "user", plan="enterprise")
    with patch("backend.models.database.AsyncSessionFactory") as factory:
        with pytest.raises(HTTPException) as exc:
            await _export_evidence("not-a-uuid", "json", tenant)
    assert exc.value.status_code == 404
    factory.assert_not_called()


@pytest.mark.asyncio
async def test_database_failure_is_reported_without_exception_details():
    tenant = TokenPayload(TENANT_ID, "user", plan="enterprise")
    context, _ = fake_session_context(error=RuntimeError("sensitive database message"))
    with patch("backend.models.database.AsyncSessionFactory", return_value=context):
        with pytest.raises(HTTPException) as exc:
            await _export_evidence(EVENT_ID, "json", tenant)
    assert exc.value.status_code == 503
    assert "sensitive database message" not in exc.value.detail
