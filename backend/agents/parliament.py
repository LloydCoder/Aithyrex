"""
AI Shield — Parliament Ensemble
=================================
Multi-model AI consensus layer for ambiguous threat evaluation.

Architecture confirmed from TwinGuard session (April 2026):
  "Two AI models must independently agree that an action is safe
   before it executes. Neither model alone can authorise a BLOCK."

Members:
  Member 1: Claude Sonnet   (Anthropic API)
  Member 2: Grok-3          (xAI API)
  Member 3: ThreatFade      (deterministic oracle — Z-score score)

Voting rules:
  2 of 3 vote BLOCK  → BLOCK  (consensus required to block)
  1 of 3 vote BLOCK  → ALERT  (minority concern — escalate)
  0 of 3 vote BLOCK  → PASS   (consensus it's safe)

When Parliament is invoked:
  MEDIUM confidence detections → Parliament evaluates
  HIGH confidence but single detector fired → Parliament evaluates
  CRITICAL or multiple detector agreement → bypass Parliament (too slow)
  CLEAN → bypass Parliament (nothing to evaluate)

Parliament runs Claude and Grok calls in PARALLEL — never sequential.
Target latency: < 2 seconds total for both API calls.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field

import structlog

from backend.agents.llm_gateway import LLMGateway, MemberVerdict, Vote, PARLIAMENT_PROMPT
from backend.core.shield_engine import Action, DetectionResult, Severity, ShieldVerdict

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

    if not any(r.detected for r in verdict.results):
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
        fired = [r for r in verdict.results if r.detected]
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
    The AI Council.

    Evaluates ambiguous ShieldVerdicts using dual AI model consensus
    plus ThreatFade as a deterministic third vote.

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

        # Build prompt for both members
        detection_report = _build_detection_report(verdict)
        prompt_preview = prompt[:500] + "..." if len(prompt) > 500 else prompt
        completion_preview = (completion or "")[:500]

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
        threatfade_vote = self._threatfade_vote(threatfade_z_score)

        # Wait for both AI members — return_exceptions prevents one failure crashing both
        results_raw = await asyncio.gather(
            claude_task, grok_task, return_exceptions=True
        )

        # Replace exceptions with ABSTAIN votes
        def safe_verdict(result, member: str) -> MemberVerdict:
            if isinstance(result, Exception):
                logger.error(f"parliament_{member}_exception", error=str(result))
                return MemberVerdict(
                    member=member, vote=Vote.ABSTAIN,
                    confidence=0.0, reasoning=f"exception: {str(result)[:80]}",
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
            # All active votes say ALLOW — this was a false positive
            final_action = Action.PASS
            final_severity = Severity.CLEAN
            consensus = True

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

    def _threatfade_vote(self, z_score: float | None) -> MemberVerdict:
        """
        Convert a validated ThreatFade Z-score to a Parliament vote.
        Missing telemetry abstains; it must never be interpreted as a clean signal.
        ThreatFade is the deterministic oracle — no API call needed.

        Z-score thresholds from ThreatFade validation:
          14.76 = Merlin QUIC C2 (confirmed malicious)
          >= 10 → BLOCK
          >= 5  → ALERT
          < 5   → ALLOW
        """
        if z_score is None:
            return MemberVerdict(
                member="threatfade",
                vote=Vote.ABSTAIN,
                confidence=0.0,
                reasoning="ThreatFade telemetry unavailable; no safety conclusion",
            )
        if z_score >= 10.0:
            return MemberVerdict(
                member="threatfade",
                vote=Vote.BLOCK,
                confidence=0.95,
                reasoning=f"ThreatFade Z-score {z_score:.2f} exceeds C2 threshold (10.0)",
            )
        elif z_score >= 5.0:
            return MemberVerdict(
                member="threatfade",
                vote=Vote.ALERT,
                confidence=0.70,
                reasoning=f"ThreatFade Z-score {z_score:.2f} is elevated but below block threshold",
            )
        else:
            return MemberVerdict(
                member="threatfade",
                vote=Vote.ALLOW,
                confidence=0.90,
                reasoning=f"ThreatFade Z-score {z_score:.2f} is within normal range",
            )


# Module-level singleton
parliament = ParliamentEnsemble()
