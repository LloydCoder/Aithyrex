"""
Aithyrex — SIEM Dispatch Service
====================================
Triggered after every detection event.
Routes to correct exporter based on tenant plan.

Free/Starter: JSON only
Pro:          JSON + Splunk HEC + CEF
Enterprise:   All formats including STIX 2.1
"""

from __future__ import annotations

import structlog

logger = structlog.get_logger(__name__)

# Plan → enabled export formats
PLAN_FORMATS: dict[str, list[str]] = {
    "free":       ["json"],
    "starter":    ["json", "csv"],
    "pro":        ["json", "csv", "splunk_hec", "cef"],
    "enterprise": ["json", "csv", "splunk_hec", "cef", "stix21"],
}


class SIEMDispatcher:
    """
    Dispatches detection events to SIEM exporters.
    Runs as background task — never blocks HTTP response.
    """

    async def dispatch(
        self,
        verdict,
        tenant_id: str,
        plan: str = "free",
    ) -> dict[str, bool]:
        """
        Export verdict to all formats enabled for this plan.

        Returns dict of format → success.
        """
        from backend.exporters.siem_exporter import (
            to_cef,
            to_csv,
            to_json,
            to_splunk_hec,
            to_stix21,
        )

        formats = PLAN_FORMATS.get(plan, ["json"])
        results: dict[str, bool] = {}

        # JSON — always available, log to structlog
        if "json" in formats:
            try:
                json_output = to_json(verdict, tenant_id)
                logger.info(
                    "siem_json_export",
                    tenant_id=tenant_id,
                    action=verdict.action,
                    severity=verdict.severity,
                    payload_len=len(json_output),
                )
                results["json"] = True
            except Exception as e:
                logger.error("siem_json_failed", error=str(e))
                results["json"] = False

        # CSV
        if "csv" in formats:
            try:
                to_csv(verdict, tenant_id)
                results["csv"] = True
            except Exception as e:
                logger.error("siem_csv_failed", error=str(e))
                results["csv"] = False

        # CEF
        if "cef" in formats:
            try:
                cef_line = to_cef(verdict, tenant_id)
                logger.info("siem_cef_export", cef=cef_line[:80])
                results["cef"] = True
            except Exception as e:
                logger.error("siem_cef_failed", error=str(e))
                results["cef"] = False

        # Splunk HEC (async HTTP)
        if "splunk_hec" in formats:
            try:
                success = await to_splunk_hec(verdict, tenant_id)
                results["splunk_hec"] = success
            except Exception as e:
                logger.error("siem_splunk_failed", error=str(e))
                results["splunk_hec"] = False

        # STIX 2.1 (Enterprise)
        if "stix21" in formats:
            try:
                bundle = to_stix21(verdict, tenant_id)
                logger.info(
                    "siem_stix21_export",
                    bundle_id=bundle.get("id"),
                    objects=len(bundle.get("objects", [])),
                )
                results["stix21"] = True
            except Exception as e:
                logger.error("siem_stix21_failed", error=str(e))
                results["stix21"] = False

        return results

    async def dispatch_alert(
        self,
        verdict,
        tenant_id: str,
        plan: str = "free",
    ) -> dict[str, bool]:
        """Deliver configured alert channels and report each channel result."""
        from backend.core.config import settings
        from backend.core.shield_engine import Severity

        if verdict.severity not in (Severity.HIGH, Severity.CRITICAL):
            return {"not_required": True}

        results: dict[str, bool] = {}
        if plan in ("pro", "enterprise") and settings.SLACK_WEBHOOK_URL:
            results["slack"] = await self._send_slack(verdict, tenant_id)
        if settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID:
            results["telegram"] = await self._send_telegram(verdict, tenant_id)
        if not results:
            results["skipped_not_configured"] = True
        return results

    async def _send_slack(self, verdict, tenant_id: str) -> bool:
        """POST alert to Slack webhook."""
        import httpx

        from backend.core.config import settings

        detectors = [r.detector for r in verdict.results if r.detected]
        payload = {
            "text": f"🛡️ *Aithyrex Alert* — `{verdict.severity.upper()}`",
            "attachments": [{
                "color": "#EF4444" if verdict.blocked else "#F59E0B",
                "fields": [
                    {"title": "Action", "value": verdict.action, "short": True},
                    {"title": "Tenant", "value": tenant_id[:16], "short": True},
                    {"title": "Detectors", "value": ", ".join(detectors), "short": False},
                ],
            }],
        }
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(settings.SLACK_WEBHOOK_URL, json=payload)
                response.raise_for_status()
            logger.info("slack_alert_sent", tenant_id=tenant_id)
            return True
        except Exception as e:
            logger.error("slack_alert_failed", error_type=type(e).__name__)
            return False

    async def _send_telegram(self, verdict, tenant_id: str) -> bool:
        """Send alert via Telegram Bot API."""
        import httpx

        from backend.core.config import settings

        emoji = "🚨" if verdict.blocked else "⚠️"
        text = (
            f"{emoji} *Aithyrex {verdict.severity.upper()}*\n"
            f"Action: `{verdict.action}`\n"
            f"Tenant: `{tenant_id[:16]}`\n"
            f"Detectors: {', '.join(r.detector for r in verdict.results if r.detected)}"
        )
        url = f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(url, json={
                    "chat_id": settings.TELEGRAM_CHAT_ID,
                    "text": text,
                    "parse_mode": "Markdown",
                })
                response.raise_for_status()
            logger.info("telegram_alert_sent", tenant_id=tenant_id)
            return True
        except Exception as e:
            logger.error("telegram_alert_failed", error_type=type(e).__name__)
            return False


# Module-level singleton
siem_dispatcher = SIEMDispatcher()
