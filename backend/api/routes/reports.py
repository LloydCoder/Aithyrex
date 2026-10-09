"""Authenticated report endpoints; unimplemented reports fail explicitly."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from backend.core.auth import TokenPayload, get_current_tenant

router = APIRouter()


@router.get("/summary")
async def detection_summary(
    tenant: Annotated[TokenPayload, Depends(get_current_tenant)],
    days: int = 7,
):
    """Return 501 until a tenant-scoped persisted summary query is implemented."""
    if days < 1 or days > 90:
        raise HTTPException(status_code=400, detail="days must be between 1 and 90")
    raise HTTPException(status_code=501, detail="Tenant-scoped report summary is not implemented")


@router.post("/compliance")
async def trigger_compliance_report(
    incident_id: str,
    tenant: Annotated[TokenPayload, Depends(get_current_tenant)],
):
    """Never pretend a report was queued or legally filed when no delivery exists."""
    if tenant.plan != "enterprise":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Enterprise plan required")
    raise HTTPException(status_code=501, detail="Compliance report delivery is not implemented")
