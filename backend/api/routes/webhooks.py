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
    derive_webhook_event_key,
    parse_provider_timestamp,
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
    event_key = derive_webhook_event_key("lemonsqueezy", payload)
    attrs = data.get("data", {}).get("attributes", {}) or {}
    resource_id = str(data.get("data", {}).get("id", "")) or None
    occurred_at = parse_provider_timestamp(attrs.get("updated_at"))
    logger.info("ls_webhook_received", event_type=event_type)

    result = await billing.process_webhook_event(
        "lemonsqueezy",
        event_key,
        payload,
        event_type,
        data,
        occurred_at,
        resource_id,
    )
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
    event_id = data.get("event_id")
    event_key = derive_webhook_event_key("paddle", payload, event_id)
    if event_key is None:
        raise HTTPException(status_code=400, detail="Missing or invalid Paddle event_id")
    event_data = data.get("data", {}) or {}
    occurred_at = parse_provider_timestamp(data.get("occurred_at"))
    resource_id = str(event_data.get("id", "")) or None
    logger.info("paddle_webhook_received", event_type=event_type)

    result = await billing.process_webhook_event(
        "paddle",
        event_key,
        payload,
        event_type,
        event_data,
        occurred_at,
        resource_id,
    )
    if result.get("status") == "retry":
        raise HTTPException(status_code=503, detail="Billing state update failed; retry webhook")
    if result.get("status") in {"rejected", "skipped"}:
        raise HTTPException(status_code=400, detail=result.get("reason", "Webhook event rejected"))
    return {"received": True, **result}
