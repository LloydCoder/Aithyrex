"""
Aithyrex — Webhook Routes
============================
POST /webhooks/lemonsqueezy  — LemonSqueezy subscription events
POST /webhooks/paddle        — Paddle subscription events (EU/Enterprise)

These routes are PUBLIC — no Clerk auth.
They verify signatures from the payment provider instead.
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, HTTPException, Request, status

from backend.core.billing import (
    billing,
    verify_lemonsqueezy_signature,
    verify_paddle_signature,
)

router = APIRouter()
logger = structlog.get_logger(__name__)


@router.post("/lemonsqueezy")
async def lemonsqueezy_webhook(request: Request):
    """
    Handle LemonSqueezy subscription webhooks.
    Verifies HMAC-SHA256 signature before processing.
    """
    payload = await request.body()
    signature = request.headers.get("X-Signature", "")

    if not verify_lemonsqueezy_signature(payload, signature):
        logger.warning("ls_webhook_invalid_signature")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    try:
        import json
        data = json.loads(payload)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type = data.get("meta", {}).get("event_name", "")
    logger.info("ls_webhook_received", event_type=event_type)

    result = await billing.handle_lemonsqueezy_event(event_type, data)
    if result.get("status") == "retry":
        raise HTTPException(status_code=503, detail="Billing state update failed; retry webhook")
    if result.get("status") in {"rejected", "skipped"}:
        raise HTTPException(status_code=400, detail=result.get("reason", "Webhook event rejected"))
    return {"received": True, **result}


@router.post("/paddle")
async def paddle_webhook(request: Request):
    """
    Handle Paddle subscription webhooks (EU/Enterprise billing).
    Verifies Paddle signature before processing.
    """
    payload = await request.body()
    signature = request.headers.get("Paddle-Signature", "")

    if not verify_paddle_signature(payload, signature):
        logger.warning("paddle_webhook_invalid_signature")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    try:
        import json
        data = json.loads(payload)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type = data.get("event_type", "")
    event_data = data.get("data", {})
    logger.info("paddle_webhook_received", event_type=event_type)

    result = await billing.handle_paddle_event(event_type, event_data)
    if result.get("status") == "retry":
        raise HTTPException(status_code=503, detail="Billing state update failed; retry webhook")
    if result.get("status") in {"rejected", "skipped"}:
        raise HTTPException(status_code=400, detail=result.get("reason", "Webhook event rejected"))
    return {"received": True, **result}
