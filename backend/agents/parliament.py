"""Aithyrex Parliament: advisory escalation for ambiguous detection findings.

The ensemble receives detector metadata only; it must not receive raw customer
prompts/completions and it is not an authorization or execution authority.

Decision rules:
- Existing BLOCK or CRITICAL findings are immutable and bypass deliberation.
- ThreatFade abstains unless an AI-text risk score has explicit calibration approval.
- Two active BLOCK votes may escalate to BLOCK; one active BLOCK vote escalates to ALERT.
- ALLOW votes never erase or downgrade an existing detector finding.
- If all members abstain or fail, preserve the original detector verdict.
- Aithyrex findings remain signals; Tinlance Agent Platform owns authorization,
  approvals, policy and governed execution.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

import structlog

from backend.agents.llm_gateway import PARLIAMENT_PROMPT, LLMGateway, MemberVerdict, Vote
from backend.core.shield_engine import Action, Severity, ShieldVerdict

logger = structlog.get_logger(__name__)


@dataclass
class ParliamentVerdict:
    """Final verdict after Parliament deliberation."""
    action: Action
    severity: Severity
    blocked: bool
    votes: list[MemberVerdict] = field(default_factory=list)
    block_votes: int = 0
    alert_votes: int = 0
    allow_votes: int = 0
    abstain_votes: int = 0
    consensus: bool = False
    latency_ms: float = 0.0
    overrode_detector: bool = False   # True if Parliament disagreed with detector


# ── Trigger conditions ────────────────────────────────────────────────────────
def should_invoke_parliament(verdict: ShieldVerdict) -> bool:
    """
    Decide whether the Parliament Ensemble should evaluate this verdict.

    Parliament is invoked for ambiguous cases only.
    Clear-cut cases bypass Parliament for speed.
    """
    # No detections — nothing to evaluate
    if verdict.action == Action.BLOCK or verdict.severity == Severity.CRITICAL:
        return False

    actionable = [
        result for result in verdict.results
        if result.detected and not result.details.get("advisory_only", False)
    ]
    if not actionable:
        return False

    # Critical findings and existing BLOCK verdicts are never delegated to Parliament.
    if verdict.severity == Severity.CRITICAL:
        critical_detectors = [
            r for r in verdict.results
            if r.detected and r.severity == Severity.CRITICAL
        ]
        if len(critical_detectors) >= 1 and any(
            r.detector == "credential_leak" for r in critical_detectors
        ):
            return False   # Credential leak is deterministic — never override

    # MEDIUM confidence detections → Parliament evaluates
    if verdict.severity == Severity.MEDIUM:
        return True

    # HIGH but only ONE detector fired → Parliament evaluates
    if verdict.severity == Severity.HIGH:
        fired = actionable
        if len(fired) == 1:
            return True

    return False


def _build_detection_report(verdict: ShieldVerdict) -> str:
    """Format detection results into a structured report for Parliament."""
    lines = []
    for r in verdict.results:
        if r.detected:
            lines.append(
                f"- Detector: {r.detector} | Severity: {r.severity} | "
                f"Confidence: {r.confidence:.0%} | MITRE: {', '.join(r.mitre_atlas) or 'none'}"
            )
    return "\n".join(lines) if lines else "No specific detections."


class ParliamentEnsemble:
    """
    The advisory AI ensemble.

    Evaluates ambiguous detector verdicts using two external model opinions.
    ThreatFade is an abstaining third member until AI-text calibration is approved.

    Usage:
        parliament = ParliamentEnsemble()
        final = await parliament.evaluate(verdict, prompt, completion)
        # final.action is the definitive verdict
    """

    def __init__(self) -> None:
        self.gateway = LLMGateway()

    async def evaluate(
        self,
        verdict: ShieldVerdict,
        prompt: str,
        completion: str | None = None,
        threatfade_z_score: float | None = None,
        threatfade_validated: bool = False,
    ) -> ParliamentVerdict:
        """
        Run Parliament Ensemble on an ambiguous ShieldVerdict.

        Args:
            verdict:            The ShieldEngine's initial verdict.
            prompt:             The original prompt under review.
            completion:         The LLM completion under review (if any).
            threatfade_z_score: ThreatFade's Z-score (used as 3rd vote).

        Returns:
            ParliamentVerdict with final action and full vote breakdown.
        """
        start = time.monotonic()

        # Hard detector decisions are immutable, even if evaluate() is called
        # directly instead of through should_invoke_parliament().
        if verdict.action == Action.BLOCK or verdict.severity == Severity.CRITICAL:
            return ParliamentVerdict(
                action=verdict.action,
                severity=verdict.severity,
                blocked=verdict.blocked or verdict.action == Action.BLOCK,
                latency_ms=round((time.monotonic() - start) * 1000, 1),
                overrode_detector=False,
            )

        # Build prompt for both members
        detection_report = _build_detection_report(verdict)
        # Never transmit customer prompts/completions to external model providers.
        # Parliament receives detector metadata only; content is withheld by design.
        prompt_preview = "[content withheld for privacy]"
        completion_preview = "[content withheld for privacy]"

        parliament_prompt = PARLIAMENT_PROMPT.format(
            detection_report=detection_report,
            prompt_preview=prompt_preview,
            completion_preview=completion_preview,
        )

        # ── Call Claude and Grok in PARALLEL ─────────────────────────────────
        claude_task = asyncio.create_task(
            self.gateway.call_claude(parliament_prompt)
        )
        grok_task = asyncio.create_task(
            self.gateway.call_grok(parliament_prompt)
        )

        # ThreatFade is the 3rd vote — deterministic from Z-score
        threatfade_vote = self._threatfade_vote(threatfade_z_score, validated=threatfade_validated)

        # Wait for both AI members — return_exceptions prevents one failure crashing both
        results_raw = await asyncio.gather(
            claude_task, grok_task, return_exceptions=True
        )

        # Replace exceptions with ABSTAIN votes
        def safe_verdict(result, member: str) -> MemberVerdict:
            if isinstance(result, Exception):
                logger.error(
                    "parliament_member_exception",
                    member=member,
                    error_type=type(result).__name__,
                )
                return MemberVerdict(
                    member=member, vote=Vote.ABSTAIN,
                    confidence=0.0, reasoning="provider_error",
                )
            return result

        claude_verdict = safe_verdict(results_raw[0], "claude")
        grok_verdict   = safe_verdict(results_raw[1], "grok")

        all_votes = [claude_verdict, grok_verdict, threatfade_vote]

        # ── Tally votes ───────────────────────────────────────────────────────
        block_votes  = sum(1 for v in all_votes if v.vote == Vote.BLOCK)
        alert_votes  = sum(1 for v in all_votes if v.vote == Vote.ALERT)
        allow_votes  = sum(1 for v in all_votes if v.vote == Vote.ALLOW)
        abstain_votes = sum(1 for v in all_votes if v.vote == Vote.ABSTAIN)

        # ── Apply voting rules ────────────────────────────────────────────────
        # Abstentions don't count — recalculate active votes
        active_votes = [v for v in all_votes if v.vote != Vote.ABSTAIN]
        active_block = sum(1 for v in active_votes if v.vote == Vote.BLOCK)
        active_total = len(active_votes)

        if active_total == 0:
            # All members abstained (all APIs down) — fall back to detector verdict
            final_action = verdict.action
            final_severity = verdict.severity
            consensus = False
            logger.warning("parliament_all_abstained_using_detector_verdict")
        elif active_block >= 2:
            # Majority BLOCK — override to BLOCK
            final_action = Action.BLOCK
            final_severity = Severity.HIGH
            consensus = True
        elif active_block == 1:
            # Minority concern — ALERT
            final_action = Action.ALERT
            final_severity = Severity.MEDIUM
            consensus = False
        else:
            # Parliament is advisory: votes cannot erase detector findings.
            # Preserve the detector verdict unless Parliament escalates it.
            final_action = verdict.action
            final_severity = verdict.severity
            consensus = False

        overrode = (final_action != verdict.action)
        latency = round((time.monotonic() - start) * 1000, 1)

        logger.info(
            "parliament_verdict",
            block_votes=block_votes,
            alert_votes=alert_votes,
            allow_votes=allow_votes,
            abstain_votes=abstain_votes,
            final_action=final_action,
            consensus=consensus,
            overrode_detector=overrode,
            latency_ms=latency,
        )

        return ParliamentVerdict(
            action=final_action,
            severity=final_severity,
            blocked=final_action == Action.BLOCK,
            votes=all_votes,
            block_votes=block_votes,
            alert_votes=alert_votes,
            allow_votes=allow_votes,
            abstain_votes=abstain_votes,
            consensus=consensus,
            latency_ms=latency,
            overrode_detector=overrode,
        )

    def _threatfade_vote(
        self,
        z_score: float | None,
        *,
        validated: bool = False,
    ) -> MemberVerdict:
        """Only calibrated AI-text scores may vote; network-derived scores otherwise abstain."""
        if z_score is None:
            return MemberVerdict(
                member="threatfade",
                vote=Vote.ABSTAIN,
                confidence=0.0,
                reasoning="ThreatFade telemetry unavailable; no safety conclusion",
            )
        if not validated:
            return MemberVerdict(
                member="threatfade",
                vote=Vote.ABSTAIN,
                confidence=0.0,
                reasoning="AI-text calibration gate not satisfied; raw ThreatFade score is advisory only",
            )
        if z_score >= 5.0:
            return MemberVerdict(
                member="threatfade",
                vote=Vote.ALERT,
                confidence=0.0,
                reasoning="Calibrated ThreatFade AI-text threshold exceeded",
            )
        return MemberVerdict(
            member="threatfade",
            vote=Vote.ABSTAIN,
            confidence=0.0,
            reasoning="Low score is not evidence that the AI interaction is safe",
        )


# Module-level singleton
parliament = ParliamentEnsemble()
