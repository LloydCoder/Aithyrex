"""
AI Shield — Shield Engine (Orchestrator)
=========================================
Central coordinator for all detection modules.

Workflow:
  1. Receive prompt + completion (or prompt-only for pre-flight check)
  2. Fan out to all registered detectors in parallel
  3. Aggregate results with confidence scoring
  4. Trigger enforcement action if threshold exceeded
  5. Export to SIEM / alert channels
  6. POST to KalevioAI if NIS2/DORA threshold met

Sprint 1 target: prompt_injection + threatfade_client wired up.
All other detectors stubbed.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"
    CLEAN    = "clean"


class Action(str, Enum):
    BLOCK  = "block"
    ALERT  = "alert"
    LOG    = "log"
    PASS   = "pass"


@dataclass
class DetectionResult:
    detector: str
    detected: bool
    severity: Severity
    confidence: float          # 0.0 – 1.0
    details: dict[str, Any] = field(default_factory=dict)
    mitre_atlas: list[str] = field(default_factory=list)


@dataclass
class ShieldVerdict:
    action: Action
    severity: Severity
    results: list[DetectionResult] = field(default_factory=list)
    blocked: bool = False
    alert_sent: bool = False
    siem_exported: bool = False
    compliance_notified: bool = False

    def detected_by(self, detector_name: str) -> bool:
        """Return True if the named detector fired a positive detection."""
        return any(
            r.detector == detector_name and r.detected
            for r in self.results
        )


class ShieldEngine:
    """
    Central orchestrator for AI Shield detection pipeline.

    Usage:
        engine = ShieldEngine()
        verdict = await engine.inspect(prompt=user_input, completion=model_output)
        if verdict.action == Action.BLOCK:
            raise SecurityError("Blocked by AI Shield")
    """

    def __init__(self) -> None:
        from backend.detectors.prompt_injection import PromptInjectionDetector
        from backend.detectors.credential_leak import CredentialLeakDetector
        from backend.detectors.covert_channel import CovertChannelDetector
        from backend.detectors.c2_behaviour import C2BehaviourDetector
        from backend.detectors.data_poisoning import DataPoisoningDetector

        self._detectors: list[Any] = [
            PromptInjectionDetector(),
            CredentialLeakDetector(),
            CovertChannelDetector(),
            C2BehaviourDetector(),
            DataPoisoningDetector(),
        ]
        logger.info("shield_engine_init", detectors=len(self._detectors))

    async def inspect(
        self,
        prompt: str,
        completion: str | None = None,
        tenant_id: str | None = None,
        model: str | None = None,
        plan: str = "free",
    ) -> ShieldVerdict:
        """
        Main inspection entry point.

        Args:
            prompt:      The input sent to the LLM.
            completion:  The LLM's output (optional for pre-flight checks).
            tenant_id:   Multi-tenant identifier for usage tracking.
            model:       Model identifier.
            plan:        Tenant billing plan for limit enforcement.

        Returns:
            ShieldVerdict with action, severity, and full detector results.
        """
        logger.info(
            "shield_inspect",
            tenant_id=tenant_id,
            model=model,
            prompt_len=len(prompt),
            has_completion=completion is not None,
        )

        # ── Block mode check (Pro+) — before any detection runs ─────────
        if tenant_id and model:
            from backend.core.block_mode import block_mode
            is_blocked, block_reason = await block_mode.is_blocked(
                tenant_id=tenant_id,
                model_id=model,
            )
            if is_blocked:
                logger.warning(
                    "blocked_model_rejected",
                    tenant_id=tenant_id,
                    model=model,
                    reason=block_reason,
                )
                return ShieldVerdict(
                    action=Action.BLOCK,
                    severity=Severity.HIGH,
                    blocked=True,
                )

            # Allowlisted models bypass detection entirely
            is_allowed = await block_mode.is_allowlisted(
                tenant_id=tenant_id,
                model_id=model,
            )
            if is_allowed:
                logger.info("allowlisted_model_bypass", tenant_id=tenant_id, model=model)
                return ShieldVerdict(action=Action.PASS, severity=Severity.CLEAN)

        # ── Tier limit check (Pro+) ──────────────────────────────────────
        if tenant_id:
            from backend.core.usage_counter import usage_counter
            within_limit, count, limit = await usage_counter.check_limit(tenant_id, plan)
            if not within_limit and plan == "free":
                logger.warning("free_tier_exhausted", tenant_id=tenant_id, count=count)
                return ShieldVerdict(
                    action=Action.BLOCK,
                    severity=Severity.INFO,
                    blocked=True,
                )
            await usage_counter.increment(tenant_id)

        if not self._detectors:
            return ShieldVerdict(action=Action.PASS, severity=Severity.CLEAN)

        # ── Fan out all detectors in parallel ────────────────────────────
        tasks = [
            detector.detect(prompt=prompt, completion=completion)
            for detector in self._detectors
        ]
        results: list[DetectionResult] = await asyncio.gather(*tasks)
        verdict = self._aggregate(results)

        # ── Parliament Ensemble (ambiguous cases only) ────────────────────
        # Clear-cut CRITICAL/CLEAN bypass Parliament for speed.
        # MEDIUM and single-detector HIGH go to Parliament for AI consensus.
        from backend.agents.parliament import parliament, should_invoke_parliament
        if should_invoke_parliament(verdict):
            try:
                # Extract ThreatFade Z-score from results for 3rd vote
                tf_z_score = 0.0
                for r in results:
                    if r.detector in ("covert_channel", "c2_behaviour"):
                        tf_z_score = max(
                            tf_z_score,
                            float(r.details.get("z_outlier", 0.0)),
                        )

                parliament_verdict = await parliament.evaluate(
                    verdict=verdict,
                    prompt=prompt,
                    completion=completion,
                    threatfade_z_score=tf_z_score,
                )

                # Parliament overrides ShieldEngine when it has consensus
                if parliament_verdict.consensus or parliament_verdict.overrode_detector:
                    verdict = ShieldVerdict(
                        action=parliament_verdict.action,
                        severity=parliament_verdict.severity,
                        blocked=parliament_verdict.blocked,
                        results=results,
                    )
                    logger.info(
                        "parliament_override_applied",
                        new_action=verdict.action,
                        block_votes=parliament_verdict.block_votes,
                        allow_votes=parliament_verdict.allow_votes,
                    )
            except Exception as e:
                # Parliament failure NEVER crashes detection pipeline
                logger.error("parliament_failed_using_detector_verdict", error=str(e))

        logger.info(
            "shield_verdict",
            action=verdict.action,
            severity=verdict.severity,
            blocked=verdict.blocked,
            tenant_id=tenant_id,
        )

        # ── Background tasks: DB logging + SIEM export (non-blocking) ──────
        # Scheduled via asyncio.ensure_future — safe inside FastAPI async context.
        # If no event loop running (unit tests), tasks are skipped gracefully.
        if tenant_id:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    from backend.core.event_logger import event_logger
                    from backend.core.siem_dispatch import siem_dispatcher
                    from backend.compliance.nis2_dora import nis2_dora

                    loop.create_task(event_logger.log_event(
                        verdict=verdict,
                        tenant_id=tenant_id,
                        model=model,
                        prompt_len=len(prompt),
                        completion_len=len(completion) if completion else 0,
                    ))
                    loop.create_task(siem_dispatcher.dispatch(
                        verdict=verdict,
                        tenant_id=tenant_id,
                        plan=plan,
                    ))
                    loop.create_task(siem_dispatcher.dispatch_alert(
                        verdict=verdict,
                        tenant_id=tenant_id,
                        plan=plan,
                    ))
                    loop.create_task(nis2_dora.evaluate(
                        verdict=verdict,
                        tenant_id=tenant_id,
                        plan=plan,
                    ))
            except RuntimeError:
                pass   # No event loop in test context — safe to skip

        return verdict

    def _aggregate(self, results: list[DetectionResult]) -> ShieldVerdict:
        """
        Aggregate detector results into a single verdict.

        Policy:
          - Any CRITICAL → BLOCK
          - Any HIGH → ALERT
          - MEDIUM or lower → LOG
        """
        detections = [r for r in results if r.detected]

        if not detections:
            return ShieldVerdict(
                action=Action.PASS,
                severity=Severity.CLEAN,
                results=results,
            )

        # Severity priority — CRITICAL is highest, CLEAN is lowest
        SEVERITY_RANK = {
            Severity.CRITICAL: 5,
            Severity.HIGH:     4,
            Severity.MEDIUM:   3,
            Severity.LOW:      2,
            Severity.INFO:     1,
            Severity.CLEAN:    0,
        }

        highest = max(detections, key=lambda r: SEVERITY_RANK.get(r.severity, 0))

        action = Action.LOG
        if highest.severity == Severity.CRITICAL:
            action = Action.BLOCK
        elif highest.severity == Severity.HIGH:
            action = Action.ALERT

        return ShieldVerdict(
            action=action,
            severity=highest.severity,
            results=results,
            blocked=action == Action.BLOCK,
        )
