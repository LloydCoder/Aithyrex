"""
AI Shield — NIS2/DORA Compliance Hooks
========================================
Posts incidents to KalevioAI when detection thresholds are crossed.

NIS2 Article 23 requires significant incident notification:
  - Within 24 hours: early warning
  - Within 72 hours: incident notification to CSIRT

Trigger conditions:
  - Any CRITICAL detection → immediate early warning
  - 3+ HIGH detections in 1 hour → incident notification
  - Credential leak involving EU data → auto-file

KalevioAI integration: POST /incidents → generates NIS2 report
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
import structlog

logger = structlog.get_logger(__name__)


class NIS2DoraHooks:
    """
    Compliance notification layer.
    Called from ShieldEngine when thresholds exceeded.
    Enterprise tier only.
    """

    def __init__(self) -> None:
        self._recent_highs: dict[str, list[datetime]] = {}  # tenant → timestamps

    async def evaluate(
        self,
        verdict,
        tenant_id: str,
        plan: str = "free",
    ) -> None:
        """
        Evaluate whether this verdict triggers a compliance notification.
        Only fires for Enterprise plan (NIS2/DORA reports are Enterprise-only).
        """
        if plan != "enterprise":
            return

        from backend.core.shield_engine import Severity

        if verdict.severity == Severity.CRITICAL:
            await self._notify_kalevio(verdict, tenant_id, urgency="critical")
            return

        if verdict.severity == Severity.HIGH:
            await self._track_high(verdict, tenant_id)

    async def _track_high(self, verdict, tenant_id: str) -> None:
        """Track HIGH events. Fire notification if 3+ in 60 minutes."""
        now = datetime.now(timezone.utc)

        if tenant_id not in self._recent_highs:
            self._recent_highs[tenant_id] = []

        # Keep only events from last 60 minutes
        cutoff = now.timestamp() - 3600
        self._recent_highs[tenant_id] = [
            ts for ts in self._recent_highs[tenant_id]
            if ts.timestamp() > cutoff
        ]
        self._recent_highs[tenant_id].append(now)

        if len(self._recent_highs[tenant_id]) >= 3:
            await self._notify_kalevio(verdict, tenant_id, urgency="high_cluster")
            self._recent_highs[tenant_id] = []  # Reset after notification

    async def _notify_kalevio(
        self,
        verdict,
        tenant_id: str,
        urgency: str = "critical",
    ) -> None:
        """POST incident to KalevioAI compliance engine."""
        from backend.core.config import settings

        if not settings.KALEVIOAI_API_URL or not settings.KALEVIOAI_API_KEY:
            logger.warning("kalevioai_not_configured", tenant_id=tenant_id)
            return

        detectors_fired = [r.detector for r in verdict.results if r.detected]
        mitre_ids = []
        for r in verdict.results:
            if r.detected:
                mitre_ids.extend(r.mitre_atlas)

        payload = {
            "source": "ai_shield",
            "tenant_id": tenant_id,
            "urgency": urgency,
            "severity": verdict.severity,
            "action": verdict.action,
            "detectors_fired": detectors_fired,
            "mitre_atlas": list(set(mitre_ids)),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "requires_nis2_report": urgency == "critical",
            "requires_dora_report": "credential_leak" in detectors_fired,
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                response = await client.post(
                    f"{settings.KALEVIOAI_API_URL}/incidents",
                    headers={
                        "X-API-Key": settings.KALEVIOAI_API_KEY,
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
                response.raise_for_status()
                logger.info(
                    "kalevioai_notified",
                    tenant_id=tenant_id,
                    urgency=urgency,
                    status=response.status_code,
                )
            except httpx.TimeoutException:
                logger.error("kalevioai_timeout", tenant_id=tenant_id)
            except httpx.HTTPStatusError as e:
                logger.error(
                    "kalevioai_http_error",
                    status=e.response.status_code,
                    tenant_id=tenant_id,
                )


# Module-level singleton
nis2_dora = NIS2DoraHooks()
