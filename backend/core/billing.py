"""Aithyrex billing and entitlement updates.

Provider webhook handlers validate signatures, deduplicate deliveries, and apply
subscription state changes in a transaction with the provider-event ledger. Raw
webhook bodies and secrets are never persisted. This module does not claim live
provider configuration or commercial readiness.
"""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

logger = structlog.get_logger(__name__)


# ── Plan detection from configured provider IDs ───────────────────────────────
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


def verify_paddle_signature(payload: bytes, signature: str, tolerance_seconds: int = 5) -> bool:
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


def parse_provider_timestamp(value: Any) -> datetime | None:
    """Parse an RFC 3339/ISO timestamp into an aware UTC datetime."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def derive_webhook_event_key(provider: str, payload: bytes, event_id: str | None = None) -> str | None:
    """Use Paddle's event ID or a stable body digest for Lemon Squeezy deliveries."""
    if provider == "paddle":
        if not isinstance(event_id, str) or not event_id or len(event_id) > 128:
            return None
        return event_id
    if provider == "lemonsqueezy":
        return "sha256:" + hashlib.sha256(payload).hexdigest()
    return None


# ── Tenant plan update ────────────────────────────────────────────────────────
async def _update_tenant_plan_in_session(
    session,
    clerk_org_id: str,
    new_plan: str,
    customer_id: str,
    provider: str,
) -> bool:
    from backend.models.models import Tenant

    result = await session.execute(
        select(Tenant)
        .where(Tenant.clerk_org_id == clerk_org_id)
        .with_for_update()
    )
    tenant = result.scalar_one_or_none()
    if tenant is None:
        logger.warning("tenant_not_found_for_billing", clerk_org_id=clerk_org_id)
        return False

    tenant.plan = new_plan
    tenant.block_mode_enabled = new_plan in ("pro", "enterprise")
    if provider == "lemonsqueezy":
        tenant.lemonsqueezy_customer_id = customer_id
    elif provider == "paddle":
        tenant.paddle_customer_id = customer_id
    tenant.updated_at = datetime.now(timezone.utc)
    return True


async def update_tenant_plan(
    clerk_org_id: str,
    new_plan: str,
    customer_id: str,
    provider: str,
    session=None,
) -> bool:
    """Update a tenant plan, optionally using the caller's transaction."""
    if session is not None:
        return await _update_tenant_plan_in_session(
            session, clerk_org_id, new_plan, customer_id, provider
        )

    try:
        from backend.models.database import AsyncSessionFactory

        async with AsyncSessionFactory() as own_session:
            async with own_session.begin():
                updated = await _update_tenant_plan_in_session(
                    own_session, clerk_org_id, new_plan, customer_id, provider
                )
        if updated:
            logger.info(
                "tenant_plan_updated",
                clerk_org_id=clerk_org_id,
                new_plan=new_plan,
                provider=provider,
            )
        return updated
    except Exception as exc:
        logger.error("tenant_plan_update_failed", error_type=type(exc).__name__)
        return False


# ── Billing webhook idempotency and ordering ─────────────────────────────────
class BillingService:
    """Processes signed provider events with transactional deduplication."""

    _LS_SUBSCRIPTION_EVENTS = {
        "subscription_created",
        "subscription_updated",
        "subscription_cancelled",
    }
    _PADDLE_SUBSCRIPTION_EVENTS = {
        "subscription.created",
        "subscription.updated",
        "subscription.resumed",
        "subscription.canceled",
        "subscription.cancelled",
        "subscription.paused",
        "subscription.past_due",
    }

    async def process_webhook_event(
        self,
        provider: str,
        event_key: str,
        payload: bytes,
        event_type: str,
        data: dict,
        occurred_at: datetime | None,
        resource_id: str | None,
    ) -> dict:
        """Deduplicate and order a webhook in the same DB transaction as entitlement updates.

        Paddle events use the provider's stable event_id. Lemon Squeezy does not
        expose a stable event ID in its documented payload, so exact retries use
        a SHA-256 body key; the per-resource timestamp guard also rejects older
        subscription snapshots. The database unique constraint serializes races.
        """
        from backend.models.database import AsyncSessionFactory
        from backend.models.models import BillingWebhookEvent, Tenant

        if provider not in {"lemonsqueezy", "paddle"}:
            return {"status": "rejected", "reason": "unsupported_provider"}
        if not isinstance(event_key, str) or not event_key or len(event_key) > 128:
            return {"status": "rejected", "reason": "invalid_event_key"}
        if resource_id is not None and len(resource_id) > 128:
            return {"status": "rejected", "reason": "invalid_resource_id"}

        payload_digest = hashlib.sha256(payload).hexdigest()
        normalized_type = event_type if isinstance(event_type, str) and event_type else "unknown"
        try:
            async with AsyncSessionFactory() as session:
                async with session.begin():
                    insert_stmt = (
                        pg_insert(BillingWebhookEvent)
                        .values(
                            id=uuid.uuid4(),
                            provider=provider,
                            event_key=event_key,
                            payload_sha256=payload_digest,
                            event_type=normalized_type[:128],
                            resource_id=resource_id[:128] if resource_id else None,
                            occurred_at=occurred_at,
                            status="processing",
                            result={},
                            received_at=datetime.now(timezone.utc),
                        )
                        .on_conflict_do_nothing(
                            index_elements=[
                                BillingWebhookEvent.provider,
                                BillingWebhookEvent.event_key,
                            ]
                        )
                        .returning(BillingWebhookEvent.id)
                    )
                    inserted_id = (await session.execute(insert_stmt)).scalar_one_or_none()
                    event_result = await session.execute(
                        select(BillingWebhookEvent)
                        .where(
                            BillingWebhookEvent.provider == provider,
                            BillingWebhookEvent.event_key == event_key,
                        )
                        .with_for_update()
                    )
                    event_row = event_result.scalar_one_or_none()
                    if event_row is None:
                        raise RuntimeError("billing_event_ledger_unavailable")

                    if inserted_id is None:
                        if event_row.payload_sha256 != payload_digest:
                            return {"status": "rejected", "reason": "event_key_payload_mismatch"}
                        if event_row.status in {"processed", "rejected", "stale"}:
                            return {"status": "duplicate", "event": normalized_type}
                        return {"status": "retry", "reason": "billing_event_in_progress"}

                    org_id = self._organization_id(provider, data)
                    recognized = self._is_subscription_event(provider, normalized_type)
                    if not org_id:
                        event_row.status = "rejected"
                        event_row.result = {"status": "rejected", "reason": "missing_clerk_org_id"}
                        event_row.processed_at = datetime.now(timezone.utc)
                        return {"status": "rejected", "reason": "missing_clerk_org_id"}

                    tenant_result = await session.execute(
                        select(Tenant)
                        .where(Tenant.clerk_org_id == org_id)
                        .with_for_update()
                    )
                    tenant = tenant_result.scalar_one_or_none()
                    if tenant is None:
                        # Roll back the ledger insert so a provider retry can succeed
                        # if tenant provisioning is briefly behind webhook delivery.
                        raise RuntimeError("billing_tenant_not_provisioned")

                    if recognized:
                        if not resource_id or occurred_at is None:
                            event_row.status = "rejected"
                            event_row.result = {
                                "status": "rejected",
                                "reason": "missing_resource_timestamp",
                            }
                            event_row.processed_at = datetime.now(timezone.utc)
                            return {"status": "rejected", "reason": "missing_resource_timestamp"}

                        latest_result = await session.execute(
                            select(BillingWebhookEvent)
                            .where(
                                BillingWebhookEvent.provider == provider,
                                BillingWebhookEvent.resource_id == resource_id,
                                BillingWebhookEvent.status == "processed",
                                BillingWebhookEvent.occurred_at.is_not(None),
                            )
                            .order_by(BillingWebhookEvent.occurred_at.desc())
                            .limit(1)
                        )
                        latest = latest_result.scalar_one_or_none()
                        if latest is not None and latest.occurred_at >= occurred_at:
                            event_row.status = "stale"
                            event_row.result = {"status": "stale", "event": normalized_type}
                            event_row.processed_at = datetime.now(timezone.utc)
                            return {"status": "stale", "event": normalized_type}

                    if provider == "lemonsqueezy":
                        result = await self.handle_lemonsqueezy_event(
                            normalized_type, data, session=session
                        )
                    elif provider == "paddle":
                        result = await self.handle_paddle_event(
                            normalized_type, data, session=session
                        )
                    else:
                        event_row.status = "rejected"
                        event_row.result = {"status": "rejected", "reason": "unsupported_provider"}
                        event_row.processed_at = datetime.now(timezone.utc)
                        return {"status": "rejected", "reason": "unsupported_provider"}

                    if result.get("status") == "retry":
                        raise RuntimeError("billing_tenant_update_failed")

                    event_row.status = (
                        "rejected" if result.get("status") in {"rejected", "skipped"} else "processed"
                    )
                    event_row.result = {
                        "status": result.get("status", "unknown"),
                        "plan": result.get("plan"),
                        "event": normalized_type,
                    }
                    event_row.processed_at = datetime.now(timezone.utc)
                    return result
        except Exception as exc:
            logger.error(
                "billing_webhook_processing_failed",
                provider=provider,
                event_type=normalized_type,
                error_type=type(exc).__name__,
            )
            return {"status": "retry", "reason": "billing_processing_unavailable"}

    @staticmethod
    def _organization_id(provider: str, data: dict) -> str:
        if provider == "lemonsqueezy":
            meta = data.get("meta", {}) or {}
            custom_data = meta.get("custom_data", {}) or {}
            value = custom_data.get("clerk_org_id", "")
        elif provider == "paddle":
            custom_data = data.get("custom_data", {}) or {}
            value = custom_data.get("clerk_org_id", "")
        else:
            value = ""
        return value if isinstance(value, str) else ""

    @classmethod
    def _is_subscription_event(cls, provider: str, event_type: str) -> bool:
        if provider == "lemonsqueezy":
            return event_type in cls._LS_SUBSCRIPTION_EVENTS
        if provider == "paddle":
            return event_type in cls._PADDLE_SUBSCRIPTION_EVENTS
        return False

    async def handle_lemonsqueezy_event(self, event_type: str, data: dict, session=None) -> dict:
        """Process recognized Lemon Squeezy subscription lifecycle events."""
        meta = data.get("meta", {}) or {}
        attrs = data.get("data", {}).get("attributes", {}) or {}
        customer_id = str(attrs.get("customer_id", ""))
        custom_data = meta.get("custom_data", {}) or {}
        clerk_org_id = custom_data.get("clerk_org_id", "")

        if not clerk_org_id:
            logger.warning("ls_webhook_missing_clerk_org_id", event_type=event_type)
            return {"status": "skipped", "reason": "missing_clerk_org_id"}

        async def apply_plan(plan: str) -> dict:
            if session is None:
                updated = await update_tenant_plan(
                    clerk_org_id, plan, customer_id, "lemonsqueezy"
                )
            else:
                updated = await update_tenant_plan(
                    clerk_org_id, plan, customer_id, "lemonsqueezy", session=session
                )
            if not updated:
                return {"status": "retry", "reason": "tenant_update_failed"}
            return {"status": "ok", "plan": plan, "event": event_type}

        if event_type in ("subscription_created", "subscription_updated"):
            variant_id = str(attrs.get("variant_id", ""))
            plan = _plan_from_ls_variant(variant_id)
            if plan is None:
                logger.warning("ls_webhook_unknown_variant", event_type=event_type)
                return {"status": "rejected", "reason": "unknown_variant_id"}
            return await apply_plan(plan)
        if event_type == "subscription_cancelled":
            return await apply_plan("free")
        return {"status": "unhandled", "event": event_type}

    async def handle_paddle_event(self, event_type: str, data: dict, session=None) -> dict:
        """Process recognized Paddle Billing subscription lifecycle events."""
        custom_data = data.get("custom_data", {}) or {}
        clerk_org_id = custom_data.get("clerk_org_id", "")
        customer_id = str(data.get("customer_id", ""))

        if not clerk_org_id:
            logger.warning("paddle_webhook_missing_clerk_org_id", event_type=event_type)
            return {"status": "skipped", "reason": "missing_clerk_org_id"}

        async def apply_plan(plan: str) -> dict:
            if session is None:
                updated = await update_tenant_plan(clerk_org_id, plan, customer_id, "paddle")
            else:
                updated = await update_tenant_plan(
                    clerk_org_id, plan, customer_id, "paddle", session=session
                )
            if not updated:
                return {"status": "retry", "reason": "tenant_update_failed"}
            return {"status": "ok", "plan": plan, "event": event_type}

        if event_type in {"subscription.created", "subscription.updated", "subscription.resumed"}:
            status = data.get("status")
            if status not in {"active", "trialing"}:
                logger.warning("paddle_subscription_not_entitled", event_type=event_type, status=status)
                return await apply_plan("free")

            items = data.get("items", [])
            if not isinstance(items, list) or len(items) != 1:
                return {"status": "rejected", "reason": "ambiguous_subscription_items"}
            price_id = str((items[0].get("price") or {}).get("id", ""))
            plan = _plan_from_paddle_price(price_id)
            if plan is None:
                logger.warning("paddle_webhook_unknown_price", event_type=event_type)
                return {"status": "rejected", "reason": "unknown_price_id"}
            return await apply_plan(plan)

        if event_type in {
            "subscription.canceled",
            "subscription.cancelled",
            "subscription.paused",
            "subscription.past_due",
        }:
            return await apply_plan("free")
        return {"status": "unhandled", "event": event_type}


# Module-level singleton
billing = BillingService()
