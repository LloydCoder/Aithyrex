"""
AI Shield — Billing Service
=============================
Unified billing handler for LemonSqueezy (global) and Paddle (EU/Enterprise).

LemonSqueezy — Global / US / Nigeria (via Paystack passthrough)
  Handles: Free → Starter → Pro upgrades
  Store ID: 247127 (same as KalevioAI and GiftMode)

Paddle — EU / Enterprise
  Handles: Pro and Enterprise tier
  VAT auto-handled for EU buyers
  Enterprise invoicing for procurement teams

Plan mapping:
  free:       500 inferences/month
  starter:    25,000 inferences/month  ($49)
  pro:        150,000 inferences/month ($199) — block mode unlocked
  enterprise: unlimited                (custom) — NIS2/DORA reports
"""

from __future__ import annotations

import hashlib
import hmac
import time
from datetime import datetime, timezone

import structlog

logger = structlog.get_logger(__name__)


# ── Plan detection from variant IDs ──────────────────────────────────────────
def _plan_from_ls_variant(variant_id: str) -> str | None:
    from backend.core.config import settings
    mapping = {}
    if settings.LEMONSQUEEZY_STARTER_VARIANT_ID:
        mapping[settings.LEMONSQUEEZY_STARTER_VARIANT_ID] = "starter"
    if settings.LEMONSQUEEZY_PRO_VARIANT_ID:
        mapping[settings.LEMONSQUEEZY_PRO_VARIANT_ID] = "pro"
    return mapping.get(str(variant_id))


def _plan_from_paddle_price(price_id: str) -> str | None:
    from backend.core.config import settings
    mapping = {}
    if settings.PADDLE_PRO_PRICE_ID:
        mapping[settings.PADDLE_PRO_PRICE_ID] = "pro"
    if settings.PADDLE_ENTERPRISE_PRICE_ID:
        mapping[settings.PADDLE_ENTERPRISE_PRICE_ID] = "enterprise"
    return mapping.get(str(price_id))


# ── Signature verification ────────────────────────────────────────────────────
def verify_lemonsqueezy_signature(payload: bytes, signature: str) -> bool:
    from backend.core.config import settings
    if not settings.LEMONSQUEEZY_WEBHOOK_SECRET or not signature:
        return False
    expected = hmac.new(
        settings.LEMONSQUEEZY_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def verify_paddle_signature(payload: bytes, signature: str, tolerance_seconds: int = 300) -> bool:
    """Verify Paddle Billing's timestamped ts=...;h1=... signature."""
    from backend.core.config import settings

    secret = settings.PADDLE_WEBHOOK_SECRET
    if not secret or not signature:
        return False

    fields = {}
    for component in signature.split(";"):
        key, separator, value = component.partition("=")
        if separator and key and value:
            fields.setdefault(key.strip(), []).append(value.strip())

    timestamps = fields.get("ts", [])
    signatures = fields.get("h1", [])
    if len(timestamps) != 1 or not signatures:
        return False

    try:
        timestamp = int(timestamps[0])
    except (TypeError, ValueError):
        return False
    if abs(time.time() - timestamp) > tolerance_seconds:
        return False

    signed_payload = str(timestamp).encode("utf-8") + b":" + payload
    expected = hmac.new(secret.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, candidate) for candidate in signatures)


# ── Tenant plan update ────────────────────────────────────────────────────────
async def update_tenant_plan(
    clerk_org_id: str,
    new_plan: str,
    customer_id: str,
    provider: str,
) -> bool:
    """
    Update a tenant's plan in PostgreSQL.
    Called from both LemonSqueezy and Paddle webhook handlers.
    """
    try:
        from sqlalchemy import select

        from backend.models.database import AsyncSessionFactory
        from backend.models.models import Tenant

        async with AsyncSessionFactory() as session:
            stmt = select(Tenant).where(Tenant.clerk_org_id == clerk_org_id)
            result = await session.execute(stmt)
            tenant = result.scalar_one_or_none()

            if not tenant:
                logger.warning("tenant_not_found_for_billing", clerk_org_id=clerk_org_id)
                return False

            tenant.plan = new_plan

            # Block mode auto-enabled for Pro+
            tenant.block_mode_enabled = new_plan in ("pro", "enterprise")

            if provider == "lemonsqueezy":
                tenant.lemonsqueezy_customer_id = customer_id
            elif provider == "paddle":
                tenant.paddle_customer_id = customer_id

            tenant.updated_at = datetime.now(timezone.utc)
            await session.commit()

            logger.info(
                "tenant_plan_updated",
                clerk_org_id=clerk_org_id,
                new_plan=new_plan,
                provider=provider,
            )
            return True

    except Exception as e:
        logger.error("tenant_plan_update_failed", error=str(e), clerk_org_id=clerk_org_id)
        return False


class BillingService:
    """
    Processes billing events from LemonSqueezy and Paddle.
    Updates tenant plans in PostgreSQL.
    """

    async def handle_lemonsqueezy_event(self, event_type: str, data: dict) -> dict:
        """
        Process LemonSqueezy webhook event.

        Events handled:
          subscription_created  → activate new plan
          subscription_updated  → plan change (upgrade/downgrade)
          subscription_cancelled → downgrade to free
          order_created         → one-time purchase
        """
        meta = data.get("meta", {})
        attrs = data.get("data", {}).get("attributes", {})
        customer_id = str(attrs.get("customer_id", ""))

        # Extract Clerk org ID from custom data
        custom_data = meta.get("custom_data", {}) or {}
        clerk_org_id = custom_data.get("clerk_org_id", "")

        if not clerk_org_id:
            logger.warning("ls_webhook_missing_clerk_org_id", event=event_type)
            return {"status": "skipped", "reason": "missing_clerk_org_id"}

        if event_type in ("subscription_created", "subscription_updated"):
            variant_id = str(attrs.get("variant_id", ""))
            plan = _plan_from_ls_variant(variant_id)
            if plan is None:
                logger.warning("ls_webhook_unknown_variant", event=event_type)
                return {"status": "rejected", "reason": "unknown_variant_id"}
            updated = await update_tenant_plan(clerk_org_id, plan, customer_id, "lemonsqueezy")
            if not updated:
                return {"status": "retry", "reason": "tenant_update_failed"}
            return {"status": "ok", "plan": plan, "event": event_type}

        elif event_type == "subscription_cancelled":
            updated = await update_tenant_plan(clerk_org_id, "free", customer_id, "lemonsqueezy")
            if not updated:
                return {"status": "retry", "reason": "tenant_update_failed"}
            return {"status": "ok", "plan": "free", "event": event_type}

        return {"status": "unhandled", "event": event_type}

    async def handle_paddle_event(self, event_type: str, data: dict) -> dict:
        """
        Process Paddle webhook event.

        Events handled:
          subscription.activated  → activate plan
          subscription.updated    → plan change
          subscription.cancelled  → downgrade
        """
        custom_data = data.get("custom_data", {}) or {}
        clerk_org_id = custom_data.get("clerk_org_id", "")
        customer_id = data.get("customer_id", "")
        price_id = ""

        items = data.get("items", [])
        if items:
            price_id = items[0].get("price", {}).get("id", "")

        if not clerk_org_id:
            logger.warning("paddle_webhook_missing_clerk_org_id", event=event_type)
            return {"status": "skipped", "reason": "missing_clerk_org_id"}

        if event_type in ("subscription.activated", "subscription.updated"):
            plan = _plan_from_paddle_price(price_id)
            if plan is None:
                logger.warning("paddle_webhook_unknown_price", event=event_type)
                return {"status": "rejected", "reason": "unknown_price_id"}
            updated = await update_tenant_plan(clerk_org_id, plan, customer_id, "paddle")
            if not updated:
                return {"status": "retry", "reason": "tenant_update_failed"}
            return {"status": "ok", "plan": plan, "event": event_type}

        elif event_type == "subscription.cancelled":
            updated = await update_tenant_plan(clerk_org_id, "free", customer_id, "paddle")
            if not updated:
                return {"status": "retry", "reason": "tenant_update_failed"}
            return {"status": "ok", "plan": "free", "event": event_type}

        return {"status": "unhandled", "event": event_type}


# Module-level singleton
billing = BillingService()
