"""
Aithyrex — Enforcement Routes (Pro tier)
==========================================
POST /enforce/block        — block a model or agent
POST /enforce/unblock      — remove from block list
POST /enforce/allow        — add model to allowlist
GET  /enforce/blocked      — list all blocked models/agents

Block mode is a Pro+ feature.
Attempted use on Free/Starter returns 403 with upgrade prompt.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from backend.core.auth import TokenPayload, get_current_tenant
from backend.core.block_mode import block_mode

router = APIRouter()


# ── Request schemas ───────────────────────────────────────────────────────────
class BlockRequest(BaseModel):
    target_type: str = Field(pattern=r"^(model|agent)$")
    target_id: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")
    reason: str = Field(default="", max_length=500)
    ttl_hours: int = Field(default=24, ge=1, le=720)


class AllowRequest(BaseModel):
    model_id: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")


# ── Plan gate ─────────────────────────────────────────────────────────────────
def require_pro(tenant: TokenPayload) -> None:
    if tenant.plan not in ("pro", "enterprise"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "block_mode_pro_required",
                "message": "Block mode requires Pro or Enterprise plan.",
                "upgrade_url": "https://www.tinlance.com/agent-as-a-service",
            },
        )


# ── Routes ────────────────────────────────────────────────────────────────────
@router.post("/block")
async def block_target(
    req: BlockRequest,
    tenant: Annotated[TokenPayload, Depends(get_current_tenant)],
):
    """Block a model or agent. Pro tier required."""
    require_pro(tenant)

    ttl_seconds = req.ttl_hours * 3600

    if req.target_type == "model":
        success = await block_mode.block_model(
            tenant_id=tenant.tenant_id,
            model_id=req.target_id,
            reason=req.reason,
            ttl=ttl_seconds,
        )
    elif req.target_type == "agent":
        success = await block_mode.block_agent(
            tenant_id=tenant.tenant_id,
            agent_id=req.target_id,
            reason=req.reason,
            ttl=ttl_seconds,
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target_type must be 'model' or 'agent'",
        )

    if not success:
        raise HTTPException(status_code=503, detail="Block state unavailable; no change was confirmed")

    return {
        "blocked": success,
        "target_type": req.target_type,
        "target_id": req.target_id,
        "reason": req.reason,
        "expires_in_hours": req.ttl_hours,
        "tenant_id": tenant.tenant_id,
    }


@router.post("/unblock")
async def unblock_target(
    req: BlockRequest,
    tenant: Annotated[TokenPayload, Depends(get_current_tenant)],
):
    """Remove a model or agent from block list."""
    require_pro(tenant)

    if req.target_type == "model":
        success = await block_mode.unblock_model(tenant.tenant_id, req.target_id)
    elif req.target_type == "agent":
        success = await block_mode.unblock_agent(tenant.tenant_id, req.target_id)
    else:
        raise HTTPException(status_code=400, detail="target_type must be 'model' or 'agent'")

    if not success:
        raise HTTPException(status_code=503, detail="Block state unavailable; no change was confirmed")

    return {
        "unblocked": success,
        "target_type": req.target_type,
        "target_id": req.target_id,
    }


@router.post("/allow")
async def allowlist_model(
    req: AllowRequest,
    tenant: Annotated[TokenPayload, Depends(get_current_tenant)],
):
    """Deprecated: model allowlisting is disabled because it bypassed mandatory inspection."""
    require_pro(tenant)
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="Model allowlisting is disabled. Mandatory detection cannot be bypassed.",
    )


@router.get("/blocked")
async def list_blocked(
    tenant: Annotated[TokenPayload, Depends(get_current_tenant)],
):
    """List all blocked models and agents for this tenant."""
    require_pro(tenant)

    blocked = await block_mode.list_blocked(tenant.tenant_id)
    return {
        "tenant_id": tenant.tenant_id,
        "blocked_count": len(blocked),
        "blocked": blocked,
    }
