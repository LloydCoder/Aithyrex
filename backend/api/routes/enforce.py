"""
AI Shield — Enforcement Routes (Pro tier)
==========================================
POST /enforce/block        — block a model or agent
POST /enforce/unblock      — remove from block list
POST /enforce/allow        — add model to allowlist
GET  /enforce/blocked      — list all blocked models/agents
GET  /enforce/rules        — list custom detection rules

Block mode is a Pro+ feature.
Attempted use on Free/Starter returns 403 with upgrade prompt.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from backend.core.auth import TokenPayload, get_current_tenant
from backend.core.block_mode import block_mode

router = APIRouter()


# ── Request schemas ───────────────────────────────────────────────────────────
class BlockRequest(BaseModel):
    target_type: str          # "model" | "agent"
    target_id: str
    reason: str = ""
    ttl_hours: int = 24       # Block duration


class AllowRequest(BaseModel):
    model_id: str


# ── Plan gate ─────────────────────────────────────────────────────────────────
def require_pro(tenant: TokenPayload) -> None:
    if tenant.plan not in ("pro", "enterprise"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "block_mode_pro_required",
                "message": "Block mode requires Pro or Enterprise plan.",
                "upgrade_url": "https://tinlance.com/ai-shield#pricing",
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
    """Add a model to the allowlist — bypasses all detection."""
    require_pro(tenant)

    success = await block_mode.allowlist_model(
        tenant_id=tenant.tenant_id,
        model_id=req.model_id,
    )
    return {
        "allowlisted": success,
        "model_id": req.model_id,
        "tenant_id": tenant.tenant_id,
    }


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
