"""Authenticated monitor ticket and WebSocket endpoints for Aithyrex."""

from __future__ import annotations

import hashlib
import secrets
from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, WebSocket, status

from backend.core.auth import TokenPayload, get_current_tenant

router = APIRouter()
logger = structlog.get_logger(__name__)
TICKET_TTL_SECONDS = 60


@router.post("/ticket")
async def create_monitor_ticket(
    tenant: Annotated[TokenPayload, Depends(get_current_tenant)],
) -> dict:
    """Mint a one-use, short-lived WebSocket ticket for an authenticated tenant."""
    try:
        from backend.core.usage_counter import usage_counter
        redis = await usage_counter._get_redis()
        if redis is None:
            raise RuntimeError("Redis unavailable")
        ticket = secrets.token_urlsafe(32)
        key = "aithyrex:ws-ticket:" + hashlib.sha256(ticket.encode("utf-8")).hexdigest()
        stored = await redis.set(key, tenant.tenant_id, ex=TICKET_TTL_SECONDS, nx=True)
        if not stored:
            raise RuntimeError("Unable to persist monitor ticket")
        return {"ticket": ticket, "expires_in_seconds": TICKET_TTL_SECONDS}
    except Exception as exc:
        logger.error("monitor_ticket_unavailable", error_type=type(exc).__name__)
        raise HTTPException(status_code=503, detail="Monitor authentication unavailable") from exc


@router.websocket("/stream")
async def monitor_stream(websocket: WebSocket):
    """Consume a one-use ticket; no long-lived Clerk token is accepted in the URL."""
    ticket = websocket.query_params.get("ticket", "")
    if not ticket or len(ticket) > 256:
        await websocket.close(code=4401, reason="Authentication required")
        return
    try:
        import hashlib
        from backend.core.usage_counter import usage_counter
        redis = await usage_counter._get_redis()
        if redis is None:
            raise RuntimeError("Redis unavailable")
        key = "aithyrex:ws-ticket:" + hashlib.sha256(ticket.encode("utf-8")).hexdigest()
        tenant_id = await redis.getdel(key)
    except Exception as exc:
        logger.error("monitor_ticket_validation_failed", error_type=type(exc).__name__)
        await websocket.close(code=1013, reason="Authentication service unavailable")
        return
    if not tenant_id:
        await websocket.close(code=4401, reason="Invalid or expired ticket")
        return
    await websocket.accept()
    await websocket.send_json({"status": "authenticated"})
    # A durable tenant-scoped event publisher is a later phase; do not claim a live feed.
    await websocket.close(code=1013, reason="Live event stream is not yet configured")
