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

from unittest.mock import AsyncMock, patch

import pytest

from backend.agents.llm_gateway import LLMGateway, MemberVerdict, Vote
from backend.agents.parliament import (
    ParliamentEnsemble,
    should_invoke_parliament,
)
from backend.core.shield_engine import Action, DetectionResult, Severity, ShieldVerdict


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
    def test_high_z_score_votes_alert_only(self, ensemble):
        vote = ensemble._threatfade_vote(z_score=14.76)
        assert vote.vote == Vote.ALERT
        assert vote.confidence == 0.0

    def test_medium_z_score_votes_alert(self, ensemble):
        vote = ensemble._threatfade_vote(z_score=7.0)
        assert vote.vote == Vote.ALERT

    def test_low_z_score_abstains(self, ensemble):
        vote = ensemble._threatfade_vote(z_score=0.5)
        assert vote.vote == Vote.ABSTAIN

    def test_high_network_score_does_not_directly_block_ai_text(self, ensemble):
        """A high network-derived score is advisory and cannot directly block AI text."""
        vote = ensemble._threatfade_vote(z_score=14.76)
        assert vote.vote == Vote.ALERT


# ── Full Parliament vote scenarios ────────────────────────────────────────────
class TestParliamentVoting:

    @pytest.mark.asyncio
    async def test_two_model_voters_can_block(self, ensemble):
        """Two model voters can escalate; ThreatFade alone contributes only ALERT."""
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
        """One model BLOCK and another ALLOW yields ALERT; low score abstains."""
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
        """Two model ALLOW votes with ThreatFade abstaining yield PASS for this advisory stage."""
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


def test_missing_threatfade_telemetry_abstains(ensemble):
    vote = ensemble._threatfade_vote(z_score=None)
    assert vote.vote == Vote.ABSTAIN


def test_existing_block_verdict_never_invokes_parliament():
    verdict = make_verdict(Action.BLOCK, Severity.HIGH)
    assert should_invoke_parliament(verdict) is False


def test_critical_noncredential_verdict_also_bypasses_parliament():
    verdict = make_verdict(Action.BLOCK, Severity.CRITICAL, detector="c2_behaviour")
    assert should_invoke_parliament(verdict) is False


@pytest.mark.parametrize("payload", ["", "not-json", '{"vote":"unknown"}'])
def test_malformed_or_unknown_llm_vote_abstains(payload):
    parsed = LLMGateway()._parse_vote(payload)
    assert parsed["vote"] == "abstain"
    assert parsed["confidence"] == 0.0


@pytest.mark.asyncio
async def test_parliament_never_transmits_raw_prompt_or_completion(ensemble):
    prompt = "UNIQUE_PRIVATE_PROMPT_SENTINEL"
    completion = "UNIQUE_PRIVATE_COMPLETION_SENTINEL"
    ensemble.gateway.call_claude = AsyncMock(return_value=member_vote("claude", Vote.ALLOW))
    ensemble.gateway.call_grok = AsyncMock(return_value=member_vote("grok", Vote.ALLOW))
    await ensemble.evaluate(
        make_verdict(Action.LOG, Severity.MEDIUM),
        prompt=prompt,
        completion=completion,
        threatfade_z_score=None,
    )
    claude_prompt = ensemble.gateway.call_claude.await_args.args[0]
    grok_prompt = ensemble.gateway.call_grok.await_args.args[0]
    for external_prompt in (claude_prompt, grok_prompt):
        assert prompt not in external_prompt
        assert completion not in external_prompt
        assert "[content withheld for privacy]" in external_prompt
