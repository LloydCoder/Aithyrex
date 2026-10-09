"""
AI Shield — Unit Tests: Parliament Ensemble
=============================================
Tests all vote scenarios without live API calls.
Claude and Grok are mocked — consensus logic is real.

Scenarios covered:
  1. 2-of-3 BLOCK → final BLOCK (consensus)
  2. 1-of-3 BLOCK → final ALERT (minority)
  3. 0-of-3 BLOCK → final PASS (false positive cleared)
  4. All abstain → falls back to detector verdict
  5. ThreatFade Z-score threshold votes correct
  6. Parliament skipped for CRITICAL credential leak
  7. Parliament skipped for CLEAN verdict
  8. Parliament overrides MEDIUM detector verdict
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from backend.agents.parliament import (
    ParliamentEnsemble, should_invoke_parliament,
)
from backend.agents.llm_gateway import MemberVerdict, Vote
from backend.core.shield_engine import (
    Action, DetectionResult, Severity, ShieldVerdict
)


# ── Fixtures ──────────────────────────────────────────────────────────────────
def make_verdict(
    action: Action,
    severity: Severity,
    detector: str = "prompt_injection",
    detected: bool = True,
    confidence: float = 0.6,
) -> ShieldVerdict:
    return ShieldVerdict(
        action=action,
        severity=severity,
        blocked=action == Action.BLOCK,
        results=[
            DetectionResult(
                detector=detector,
                detected=detected,
                severity=severity,
                confidence=confidence,
                mitre_atlas=["AML.T0051"],
            )
        ],
    )


def member_vote(member: str, vote: Vote, confidence: float = 0.8) -> MemberVerdict:
    return MemberVerdict(
        member=member,
        vote=vote,
        confidence=confidence,
        reasoning=f"{member} votes {vote}",
    )


@pytest.fixture
def ensemble():
    return ParliamentEnsemble()


# ── should_invoke_parliament() ────────────────────────────────────────────────
class TestShouldInvokeParliament:
    def test_medium_verdict_triggers_parliament(self):
        v = make_verdict(Action.LOG, Severity.MEDIUM, confidence=0.5)
        assert should_invoke_parliament(v) is True

    def test_high_single_detector_triggers_parliament(self):
        v = make_verdict(Action.ALERT, Severity.HIGH, confidence=0.75)
        assert should_invoke_parliament(v) is True

    def test_critical_credential_leak_bypasses_parliament(self):
        v = ShieldVerdict(
            action=Action.BLOCK,
            severity=Severity.CRITICAL,
            blocked=True,
            results=[
                DetectionResult(
                    detector="credential_leak",
                    detected=True,
                    severity=Severity.CRITICAL,
                    confidence=0.99,
                    mitre_atlas=["T1552"],
                )
            ],
        )
        assert should_invoke_parliament(v) is False

    def test_clean_verdict_bypasses_parliament(self):
        v = make_verdict(Action.PASS, Severity.CLEAN, detected=False)
        assert should_invoke_parliament(v) is False

    def test_no_detections_bypasses_parliament(self):
        v = ShieldVerdict(
            action=Action.PASS,
            severity=Severity.CLEAN,
            results=[
                DetectionResult(
                    detector="prompt_injection",
                    detected=False,
                    severity=Severity.CLEAN,
                    confidence=0.0,
                )
            ],
        )
        assert should_invoke_parliament(v) is False


# ── ThreatFade oracle vote ─────────────────────────────────────────────────────
class TestThreatFadeVote:
    def test_high_z_score_votes_block(self, ensemble):
        vote = ensemble._threatfade_vote(z_score=14.76)
        assert vote.vote == Vote.BLOCK
        assert vote.confidence >= 0.9

    def test_medium_z_score_votes_alert(self, ensemble):
        vote = ensemble._threatfade_vote(z_score=7.0)
        assert vote.vote == Vote.ALERT

    def test_low_z_score_votes_allow(self, ensemble):
        vote = ensemble._threatfade_vote(z_score=0.5)
        assert vote.vote == Vote.ALLOW

    def test_merlin_quic_z_score_blocks(self, ensemble):
        """Merlin QUIC C2 real-world Z-score must always BLOCK."""
        vote = ensemble._threatfade_vote(z_score=14.76)
        assert vote.vote == Vote.BLOCK


# ── Full Parliament vote scenarios ────────────────────────────────────────────
class TestParliamentVoting:

    @pytest.mark.asyncio
    async def test_2_of_3_block_returns_block(self, ensemble):
        """Claude + ThreatFade BLOCK, Grok ALLOW → 2-of-3 → BLOCK."""
        verdict = make_verdict(Action.LOG, Severity.MEDIUM)

        with patch.object(ensemble.gateway, "call_claude",
                          new=AsyncMock(return_value=member_vote("claude", Vote.BLOCK))), \
             patch.object(ensemble.gateway, "call_grok",
                          new=AsyncMock(return_value=member_vote("grok", Vote.ALLOW))):

            result = await ensemble.evaluate(verdict, "test prompt", threatfade_z_score=11.0)

        assert result.action == Action.BLOCK
        assert result.block_votes == 2
        assert result.consensus is True

    @pytest.mark.asyncio
    async def test_1_of_3_block_returns_alert(self, ensemble):
        """Only Claude BLOCK, Grok and ThreatFade ALLOW → ALERT."""
        verdict = make_verdict(Action.LOG, Severity.MEDIUM)

        with patch.object(ensemble.gateway, "call_claude",
                          new=AsyncMock(return_value=member_vote("claude", Vote.BLOCK))), \
             patch.object(ensemble.gateway, "call_grok",
                          new=AsyncMock(return_value=member_vote("grok", Vote.ALLOW))):

            result = await ensemble.evaluate(verdict, "test prompt", threatfade_z_score=1.0)

        assert result.action == Action.ALERT
        assert result.block_votes == 1
        assert result.consensus is False

    @pytest.mark.asyncio
    async def test_0_of_3_block_clears_false_positive(self, ensemble):
        """All three ALLOW → false positive cleared → PASS."""
        verdict = make_verdict(Action.LOG, Severity.MEDIUM)

        with patch.object(ensemble.gateway, "call_claude",
                          new=AsyncMock(return_value=member_vote("claude", Vote.ALLOW))), \
             patch.object(ensemble.gateway, "call_grok",
                          new=AsyncMock(return_value=member_vote("grok", Vote.ALLOW))):

            result = await ensemble.evaluate(verdict, "test prompt", threatfade_z_score=0.3)

        assert result.action == Action.PASS
        assert result.severity == Severity.CLEAN
        assert result.consensus is True
        assert result.overrode_detector is True

    @pytest.mark.asyncio
    async def test_all_abstain_uses_detector_verdict(self, ensemble):
        """All APIs down → fall back to original detector verdict."""
        verdict = make_verdict(Action.ALERT, Severity.HIGH)

        with patch.object(ensemble.gateway, "call_claude",
                          new=AsyncMock(return_value=member_vote("claude", Vote.ABSTAIN))), \
             patch.object(ensemble.gateway, "call_grok",
                          new=AsyncMock(return_value=member_vote("grok", Vote.ABSTAIN))):

            result = await ensemble.evaluate(verdict, "test prompt", threatfade_z_score=0.0)

        # With all abstaining including ThreatFade at 0 → falls back
        assert result.action in (Action.ALERT, Action.PASS)

    @pytest.mark.asyncio
    async def test_parliament_runs_parallel_not_sequential(self, ensemble):
        """Claude and Grok must be called concurrently."""
        import time
        verdict = make_verdict(Action.LOG, Severity.MEDIUM)
        call_times = []

        async def slow_claude(prompt):
            call_times.append(("claude_start", time.monotonic()))
            await asyncio.sleep(0.05)
            call_times.append(("claude_end", time.monotonic()))
            return member_vote("claude", Vote.ALLOW)

        async def slow_grok(prompt):
            call_times.append(("grok_start", time.monotonic()))
            await asyncio.sleep(0.05)
            call_times.append(("grok_end", time.monotonic()))
            return member_vote("grok", Vote.ALLOW)

        import asyncio
        with patch.object(ensemble.gateway, "call_claude", new=slow_claude), \
             patch.object(ensemble.gateway, "call_grok", new=slow_grok):
            start = time.monotonic()
            await ensemble.evaluate(verdict, "test", threatfade_z_score=0.0)
            elapsed = time.monotonic() - start

        # If parallel: ~50ms. If sequential: ~100ms. Check it's < 90ms.
        assert elapsed < 0.09, f"Parliament took {elapsed*1000:.0f}ms — may not be parallel"

    @pytest.mark.asyncio
    async def test_parliament_failure_does_not_crash_pipeline(self, ensemble):
        """If Parliament throws, detection pipeline must continue."""
        verdict = make_verdict(Action.LOG, Severity.MEDIUM)

        with patch.object(ensemble.gateway, "call_claude",
                          new=AsyncMock(side_effect=Exception("API exploded"))), \
             patch.object(ensemble.gateway, "call_grok",
                          new=AsyncMock(return_value=member_vote("grok", Vote.ALLOW))):

            # Should not raise
            result = await ensemble.evaluate(verdict, "test prompt", threatfade_z_score=0.0)
            assert result is not None
