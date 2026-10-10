"""Tenant-scoped report endpoints and privacy-safe compliance evidence exports."""
from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from sqlalchemy import select

from backend.core.auth import TokenPayload, get_current_tenant

logger = structlog.get_logger(__name__)
router = APIRouter()
ExportFormat = Literal["json", "csv", "markdown"]


@router.get("/summary")
async def detection_summary(
    tenant: Annotated[TokenPayload, Depends(get_current_tenant)],
    days: int = 7,
):
    """Return 501 until a tenant-scoped persisted summary query is implemented."""
    if days < 1 or days > 90:
        raise HTTPException(status_code=400, detail="days must be between 1 and 90")
    raise HTTPException(status_code=501, detail="Tenant-scoped report summary is not implemented")


async def _export_evidence(event_id: str, export_format: ExportFormat, tenant: TokenPayload) -> Response:
    """Build a tenant-bound export from persisted event metadata, never raw prompt text."""
    if tenant.plan != "enterprise":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Enterprise plan required")
    try:
        parsed_event_id = UUID(event_id)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=404, detail="Evidence event not found") from None
    try:
        tenant_uuid = UUID(tenant.tenant_id)
    except (ValueError, TypeError, AttributeError):
        logger.error("compliance_export_invalid_tenant_binding")
        raise HTTPException(status_code=503, detail="Tenant evidence scope unavailable") from None

    try:
        from backend.compliance.evidence_export import (
            build_export_envelope,
            render_csv,
            render_json,
            render_markdown,
        )
        from backend.models.database import AsyncSessionFactory
        from backend.models.models import DetectionEvent

        async with AsyncSessionFactory() as session:
            result = await session.execute(
                select(DetectionEvent).where(
                    DetectionEvent.id == parsed_event_id,
                    DetectionEvent.tenant_id == tenant_uuid,
                )
            )
            event = result.scalar_one_or_none()
    except Exception as exc:
        logger.error("compliance_export_evidence_lookup_failed", error_type=type(exc).__name__)
        raise HTTPException(status_code=503, detail="Persisted evidence is temporarily unavailable") from None

    if event is None:
        raise HTTPException(status_code=404, detail="Evidence event not found")

    envelope = build_export_envelope(event, tenant_id=str(tenant_uuid))
    renderers = {
        "json": (render_json, "application/json", "json"),
        "csv": (render_csv, "text/csv", "csv"),
        "markdown": (render_markdown, "text/markdown", "md"),
    }
    renderer, media_type, extension = renderers[export_format]
    return Response(
        content=renderer(envelope),
        media_type=media_type,
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "X-Aithyrex-Evidence-Digest": envelope["evidence_digest"],
            "Content-Disposition": f'attachment; filename="aithyrex-compliance-evidence-{parsed_event_id}.{extension}"',
        },
    )


@router.get("/compliance/{event_id}")
async def export_compliance_evidence(
    event_id: str,
    tenant: Annotated[TokenPayload, Depends(get_current_tenant)],
    format: ExportFormat = "json",
):
    """Export persisted Enterprise evidence; this does not submit a filing."""
    return await _export_evidence(event_id, format, tenant)


@router.post("/compliance")
async def trigger_compliance_report(
    incident_id: str,
    tenant: Annotated[TokenPayload, Depends(get_current_tenant)],
    format: ExportFormat = "json",
):
    """Compatibility route; incident_id is a legacy alias for a persisted event UUID.

    This route creates an evidence export only. It does not file, notify a regulator,
    or assert that any NIS2/DORA reporting obligation has been legally satisfied.
    """
    return await _export_evidence(incident_id, format, tenant)
