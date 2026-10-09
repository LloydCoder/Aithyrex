"""
Aithyrex Sync — Olvrix Integration Bridge
=========================================
The 7th bridge in the Olvrix flywheel ecosystem.

Adds to the existing 6:
  threatfade_sync, reconos_sync, hezcast_sync,
  fadereach_sync, resonaforge_sync, flywheel_orchestrator

Registers in flywheel_orchestrator.py as:
  "ai_shield": AIShieldSync()

Four event handlers:

  Wire A — handle_business_scraped()
    Olvrix Scraper (VPS 4) scrapes 200 businesses/day.
    Scraped HTML may contain indirect prompt injection
    payloads designed to hijack Olvrix's AI analysis.
    Aithyrex scans HTML before it reaches BusinessClassifier.

  Wire B — handle_website_generated()
    Olvrix AI Engine (VPS 2, Ollama) generates website copy.
    Aithyrex scans generated HTML before the site goes live.
    Catches: credential leaks, covert channels, C2 patterns.

  Wire C — handle_outreach_generated()
    Olvrix Outreach (VPS 3) sends via Evolution API/Listmonk.
    AI Shield scans generated messages before they're sent.
    Prevents: injected outreach messages at 200/day scale.

  Wire D — handle_security_event()
    ThreatFade flags a business site with HIGH/CRITICAL C2.
    AI Shield escalates to FusionOps AI_AGENT_ABUSE category.
    TwinGuard receives escalation → agent quarantined.

Deployment:
  Add to olvrix-bridge/flywheel_orchestrator.py:
    from ai_shield_sync import AIShieldSync
    "ai_shield": AIShieldSync()

Environment:
  AITHYREX_API_URL=<verified HTTPS service URL>
  AITHYREX_API_TOKEN=<Clerk session JWT>
"""

from __future__ import annotations

import hashlib
import math
import os
from typing import Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)

AITHYREX_API_URL = os.getenv("AITHYREX_API_URL", os.getenv("AI_SHIELD_API_URL", "")).rstrip("/")
AITHYREX_API_TOKEN = os.getenv("AITHYREX_API_TOKEN", os.getenv("AI_SHIELD_API_KEY", ""))

# Z-score threshold for ThreatFade escalation to AI Shield
ESCALATION_Z_THRESHOLD = 7.0

# Olvrix plan for billing purposes (Pro - 150K inferences/month)
OLVRIX_PLAN = "pro"
OLVRIX_TENANT_ID = os.getenv("OLVRIX_TENANT_ID", "olvrix-main")


class AIShieldSync:
    """
    Olvrix → AI Shield event bridge.

    Connects Olvrix's flywheel to AI Shield's detection API.
    All inspections are fire-and-forget for the main pipeline
    but BLOCK decisions halt the workflow.
    """

    def __init__(self) -> None:
        self._headers = {
            "Authorization": f"Bearer {AITHYREX_API_TOKEN}",
            "Content-Type": "application/json",
        }
        logger.info(
            "ai_shield_sync_init",
            api_url_configured=bool(AITHYREX_API_URL),
            token_configured=bool(AITHYREX_API_TOKEN),
        )

    # ── Wire A: Scraper ───────────────────────────────────────────────────────
    async def handle_business_scraped(
        self,
        html: str,
        business_id: str,
        url: str = "",
    ) -> dict:
        """
        Scan scraped HTML for indirect injection payloads.
        Called by olvrix-intelligence/classifier.py before classification.

        Returns:
            {"safe": bool, "action": str, "severity": str}

        If safe=False, the caller should quarantine the business
        for manual review rather than passing it to AI classification.
        """
        if not html.strip():
            return {"safe": True, "action": "pass", "severity": "clean"}

        # Hash content for logging — never send raw PII to AI Shield
        content_hash = hashlib.sha256(html.encode()).hexdigest()[:16]

        # Truncate to avoid huge payloads — first 4K chars cover injection
        scan_content = html[:4096]

        result = await self._call_shield(
            prompt=scan_content,
            model="olvrix-scraper",
            source="business_scraped",
            business_id=business_id,
        )

        if result.get("blocked"):
            logger.warning(
                "olvrix_scraped_content_blocked",
                business_id=business_id,
                url=url,
                severity=result.get("severity"),
                content_hash=content_hash,
            )
            return {
                "safe": False,
                "action": result.get("action", "block"),
                "severity": result.get("severity", "high"),
                "business_id": business_id,
                "reason": "indirect_injection_detected",
            }

        return {"safe": True, "action": "pass", "severity": "clean"}

    # ── Wire B: AI Engine ─────────────────────────────────────────────────────
    async def handle_website_generated(
        self,
        html: str,
        business_id: str,
        model: str = "ollama-deepseek",
    ) -> dict:
        """
        Scan AI-generated website HTML before deployment.
        Called after Olvrix AI Engine generates site content.

        Catches:
          - Credential leaks in generated HTML (API keys exposed)
          - Covert channel patterns (poisoned Ollama model output)
          - C2 beaconing injected into generated code
        """
        if not html.strip():
            return {"safe": True, "action": "pass", "severity": "clean"}

        result = await self._call_shield(
            prompt="website generation request",
            completion=html[:8192],   # Scan more of the generated content
            model=model,
            source="website_generated",
            business_id=business_id,
        )

        if result.get("blocked"):
            logger.critical(
                "olvrix_generated_website_blocked",
                business_id=business_id,
                model=model,
                severity=result.get("severity"),
                detections=[d["detector"] for d in result.get("detections", [])],
            )
            return {
                "safe": False,
                "action": "block_deployment",
                "severity": result.get("severity"),
                "business_id": business_id,
                "reason": "generated_content_threat_detected",
            }

        return {"safe": True, "action": "pass", "severity": "clean"}

    # ── Wire C: Outreach ──────────────────────────────────────────────────────
    async def handle_outreach_generated(
        self,
        message: str,
        channel: str,
        business_id: str,
        model: str = "ollama-llama",
    ) -> dict:
        """
        Scan outreach message before Evolution API sends it.
        Called by olvrix-outreach before WhatsApp/email/SMS send.

        At 200 messages/day, one injected message reaching all
        recipients = brand damage at scale.

        Args:
            message:     Generated outreach message text
            channel:     "whatsapp" | "email" | "sms"
            business_id: Target business identifier
            model:       Model that generated the message
        """
        if not message.strip():
            return {"safe": True, "action": "pass", "severity": "clean"}

        result = await self._call_shield(
            prompt="generate personalised outreach message",
            completion=message,
            model=model,
            source=f"outreach_{channel}",
            business_id=business_id,
        )

        if result.get("blocked"):
            logger.warning(
                "olvrix_outreach_blocked",
                business_id=business_id,
                channel=channel,
                severity=result.get("severity"),
            )
            return {
                "safe": False,
                "action": "block_send",
                "severity": result.get("severity"),
                "business_id": business_id,
                "channel": channel,
                "reason": "outreach_threat_detected",
            }

        return {"safe": True, "action": "pass", "severity": "clean"}

    # ── Wire D: ThreatFade escalation ─────────────────────────────────────────
    async def handle_security_event(
        self,
        threatfade_result: dict,
        business_id: str,
        url: str = "",
    ) -> dict:
        """
        Escalate ThreatFade HIGH/CRITICAL findings to AI Shield.
        Called by threatfade_sync when z_outlier exceeds threshold.

        AI Shield escalates to FusionOps AI_AGENT_ABUSE category.
        FusionOps routes to TwinGuard kill switch if needed.

        Args:
            threatfade_result: Full ThreatFade detection result
            business_id:       Business that triggered the detection
            url:               The URL that was scanned
        """
        try:
            z_outlier = float(threatfade_result["z_outlier"])
        except (KeyError, TypeError, ValueError):
            return {"escalated": False, "degraded": True, "reason": "invalid_threatfade_signal"}
        if not math.isfinite(z_outlier):
            return {"escalated": False, "degraded": True, "reason": "invalid_threatfade_signal"}

        if z_outlier < ESCALATION_Z_THRESHOLD:
            return {"escalated": False, "z_outlier": z_outlier}

        logger.warning(
            "olvrix_threatfade_escalation",
            business_id=business_id,
            z_outlier=z_outlier,
            mitre_ttp=threatfade_result.get("mitre_ttp"),
            url=url,
        )

        # Send to AI Shield with the ThreatFade context embedded
        escalation_prompt = (
            f"ThreatFade escalation: business {business_id} at {url} "
            f"triggered Z-score {z_outlier:.2f}. "
            f"MITRE TTP: {threatfade_result.get('mitre_ttp', 'unknown')}. "
            f"Confidence: {threatfade_result.get('confidence', 'unknown')}."
        )

        result = await self._call_shield(
            prompt=escalation_prompt,
            model="threatfade-oracle",
            source="threatfade_escalation",
            business_id=business_id,
        )

        # Now escalate to FusionOps AI_AGENT_ABUSE category
        notified = await self._escalate_to_fusionops(
            business_id=business_id,
            z_outlier=z_outlier,
            threatfade_result=threatfade_result,
            shield_result=result,
        )

        return {
            "escalated": True,
            "z_outlier": z_outlier,
            "shield_action": result.get("action"),
            "degraded": bool(result.get("degraded")),
            "fusionops_notified": notified,
        }

    # ── FusionOps escalation ──────────────────────────────────────────────────
    async def _escalate_to_fusionops(
        self,
        business_id: str,
        z_outlier: float,
        threatfade_result: dict,
        shield_result: dict,
    ) -> bool:
        """POST to FusionOps only when an explicit authenticated endpoint is configured."""
        fusionops_url = os.getenv("FUSIONOPS_API_URL", "").rstrip("/")
        fusionops_key = os.getenv("FUSIONOPS_API_KEY", "")
        if not fusionops_url or not fusionops_key:
            logger.warning("fusionops_escalation_not_configured", business_id=business_id)
            return False

        payload = {
            "source": "olvrix_aithyrex_sync",
            "category": "AI_AGENT_ABUSE",
            "business_id": business_id,
            "z_outlier": z_outlier,
            "threatfade": threatfade_result,
            "aithyrex": shield_result,
        }

        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                response = await client.post(
                    f"{fusionops_url}/detect/llm",
                    headers={"X-API-Key": fusionops_key, "Content-Type": "application/json"},
                    json=payload,
                )
                response.raise_for_status()
                logger.info("fusionops_escalation_sent", business_id=business_id)
                return True
            except Exception as exc:
                logger.error("fusionops_escalation_failed", error_type=type(exc).__name__)
                return False

    # ── Core HTTP call ────────────────────────────────────────────────────────
    async def _call_shield(
        self,
        prompt: str,
        completion: Optional[str] = None,
        model: str = "olvrix",
        source: str = "",
        business_id: str = "",
    ) -> dict:
        """Call the configured Aithyrex inspection endpoint; failures are degraded blocks."""
        if not AITHYREX_API_URL or not AITHYREX_API_TOKEN:
            logger.warning("aithyrex_inspection_not_configured", source=source, business_id=business_id)
            return {"action": "block", "severity": "high", "blocked": True, "detections": [], "degraded": True, "error_code": "not_configured"}

        payload: dict = {
            "prompt": prompt,
            "model": model,
        }
        if completion:
            payload["completion"] = completion

        async with httpx.AsyncClient(timeout=8.0) as client:
            try:
                response = await client.post(
                    f"{AITHYREX_API_URL}/api/v1/detect/llm",
                    headers=self._headers,
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
                if (
                    isinstance(data, dict)
                    and data.get("action") in {"pass", "log", "alert", "block"}
                    and data.get("severity") in {"clean", "info", "low", "medium", "high", "critical"}
                    and isinstance(data.get("blocked"), bool)
                    and isinstance(data.get("detections"), list)
                ):
                    if data["action"] == "block":
                        data["blocked"] = True
                    data.setdefault("degraded", False)
                    return data
                logger.warning("aithyrex_inspection_degraded", source=source, business_id=business_id, error_code="invalid_response_schema")
                return {"action": "block", "severity": "high", "blocked": True, "detections": [], "degraded": True, "error_code": "invalid_response_schema"}

            except httpx.TimeoutException:
                logger.warning(
                    "aithyrex_inspection_timeout",
                    source=source,
                    business_id=business_id,
                )
                return {"action": "block", "severity": "high", "blocked": True, "detections": [], "degraded": True, "error_code": "inspection_unavailable"}

            except httpx.ConnectError:
                logger.warning("aithyrex_inspection_unreachable", source=source)
                return {"action": "block", "severity": "high", "blocked": True, "detections": [], "degraded": True, "error_code": "unreachable"}

            except Exception as exc:
                logger.error("aithyrex_inspection_failed", error_type=type(exc).__name__, source=source)
                return {"action": "block", "severity": "high", "blocked": True, "detections": [], "degraded": True, "error_code": "unexpected_error"}


AithyrexSync = AIShieldSync
