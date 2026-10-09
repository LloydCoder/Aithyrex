"""
AI Shield — LLM Gateway
=========================
4-layer LLM fallback chain for Parliament Ensemble voting.
Pattern reused from KalevioAI llm_gateway.py.

Layer 1: Claude Sonnet 4   (primary — Anthropic API)
Layer 2: Grok-3            (fallback — xAI API)
Layer 3: Gemini 2.5 Flash  (emergency fallback — Google API)
Layer 4: Offline verdict    (if all APIs fail — returns abstain)

Each parliament member gets its own isolated gateway call.
Members never share context — independence is the entire point.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum

import httpx
import structlog

from backend.core.config import settings

logger = structlog.get_logger(__name__)


class Vote(str, Enum):
    BLOCK   = "block"
    ALERT   = "alert"
    ALLOW   = "allow"
    ABSTAIN = "abstain"   # API unavailable — counts as no vote


@dataclass
class MemberVerdict:
    member: str          # "claude" | "grok" | "gemini" | "offline"
    vote: Vote
    confidence: float    # 0.0 – 1.0
    reasoning: str
    latency_ms: float = 0.0


# ── Prompt template ───────────────────────────────────────────────────────────
PARLIAMENT_PROMPT = """You are a cybersecurity AI on the Aithyrex Parliament Ensemble.
Your role: evaluate whether this AI model traffic represents a genuine threat.

DETECTION REPORT:
{detection_report}

PROMPT UNDER REVIEW:
{prompt_preview}

COMPLETION UNDER REVIEW:
{completion_preview}

Respond ONLY with valid JSON. No explanation outside the JSON.

{{
  "vote": "block" | "alert" | "allow" | "abstain",
  "confidence": 0.0-1.0,
  "reasoning": "one sentence explaining your vote"
}}

Rules:
- vote "block" only if you are highly confident this is malicious
- vote "alert" if suspicious but not certain
- vote "allow" only when the provided detector evidence clearly supports a false positive
- vote "abstain" when evidence is incomplete, telemetry is missing, or confidence is insufficient
- Do not infer authorization or claim the system is safe from limited detector metadata
- These votes are advisory and cannot override a deterministic BLOCK or Platform policy"""


class LLMGateway:
    """
    Multi-provider LLM gateway for Parliament Ensemble.
    Each call is independent — members cannot see each other's votes.
    """

    async def call_claude(self, prompt: str) -> MemberVerdict:
        """Call Claude Sonnet — Parliament Member 1."""
        import time
        start = time.monotonic()

        if not settings.ANTHROPIC_API_KEY:
            logger.warning("claude_api_key_missing_abstaining")
            return MemberVerdict(
                member="claude", vote=Vote.ABSTAIN,
                confidence=0.0, reasoning="API key not configured",
            )

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                response = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": settings.ANTHROPIC_API_KEY,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": "claude-sonnet-4-6",
                        "max_tokens": 256,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                )
                response.raise_for_status()
                data = response.json()
                text = data["content"][0]["text"].strip()
                parsed = self._parse_vote(text)
                latency = round((time.monotonic() - start) * 1000, 1)
                logger.info("parliament_claude_vote", vote=parsed["vote"], latency_ms=latency)
                return MemberVerdict(
                    member="claude",
                    vote=Vote(parsed["vote"]),
                    confidence=float(parsed.get("confidence", 0.7)),
                    reasoning=parsed.get("reasoning", ""),
                    latency_ms=latency,
                )
            except (httpx.TimeoutException, httpx.ConnectError):
                logger.warning("claude_timeout_abstaining")
                return MemberVerdict(
                    member="claude", vote=Vote.ABSTAIN,
                    confidence=0.0, reasoning="timeout",
                )
            except Exception as e:
                logger.error("claude_gateway_error", error_type=type(e).__name__)
                return MemberVerdict(
                    member="claude", vote=Vote.ABSTAIN,
                    confidence=0.0, reasoning="provider_error",
                )

    async def call_grok(self, prompt: str) -> MemberVerdict:
        """Call Grok-3 — Parliament Member 2."""
        import time
        start = time.monotonic()

        if not settings.GROK_API_KEY:
            logger.warning("grok_api_key_missing_abstaining")
            return MemberVerdict(
                member="grok", vote=Vote.ABSTAIN,
                confidence=0.0, reasoning="API key not configured",
            )

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                response = await client.post(
                    "https://api.x.ai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {settings.GROK_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": "grok-3",
                        "max_tokens": 256,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                )
                response.raise_for_status()
                data = response.json()
                text = data["choices"][0]["message"]["content"].strip()
                parsed = self._parse_vote(text)
                latency = round((time.monotonic() - start) * 1000, 1)
                logger.info("parliament_grok_vote", vote=parsed["vote"], latency_ms=latency)
                return MemberVerdict(
                    member="grok",
                    vote=Vote(parsed["vote"]),
                    confidence=float(parsed.get("confidence", 0.7)),
                    reasoning=parsed.get("reasoning", ""),
                    latency_ms=latency,
                )
            except (httpx.TimeoutException, httpx.ConnectError):
                logger.warning("grok_timeout_abstaining")
                return MemberVerdict(
                    member="grok", vote=Vote.ABSTAIN,
                    confidence=0.0, reasoning="timeout",
                )
            except Exception as e:
                logger.error("grok_gateway_error", error_type=type(e).__name__)
                return MemberVerdict(
                    member="grok", vote=Vote.ABSTAIN,
                    confidence=0.0, reasoning=str(e)[:100],
                )

    async def call_gemini(self, prompt: str) -> MemberVerdict:
        """Call Gemini 2.5 Flash — Emergency fallback Member."""
        import time
        start = time.monotonic()

        if not settings.GEMINI_API_KEY:
            return MemberVerdict(
                member="gemini", vote=Vote.ABSTAIN,
                confidence=0.0, reasoning="API key not configured",
            )

        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                response = await client.post(
                    "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
                    headers={"x-goog-api-key": settings.GEMINI_API_KEY},
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {"maxOutputTokens": 256},
                    },
                )
                response.raise_for_status()
                data = response.json()
                text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
                parsed = self._parse_vote(text)
                latency = round((time.monotonic() - start) * 1000, 1)
                return MemberVerdict(
                    member="gemini",
                    vote=Vote(parsed["vote"]),
                    confidence=float(parsed.get("confidence", 0.7)),
                    reasoning=parsed.get("reasoning", ""),
                    latency_ms=latency,
                )
            except Exception as e:
                logger.error("gemini_gateway_error", error_type=type(e).__name__)
                return MemberVerdict(
                    member="gemini", vote=Vote.ABSTAIN,
                    confidence=0.0, reasoning=str(e)[:100],
                )

    def _parse_vote(self, text: str) -> dict:
        """Parse LLM JSON response. Handles markdown fences."""
        # Strip markdown fences if present
        clean = text.replace("```json", "").replace("```", "").strip()
        try:
            data = json.loads(clean)
            # Validate vote value
            if data.get("vote") not in ("block", "alert", "allow", "abstain"):
                data["vote"] = "abstain"  # Invalid model output is not a safety decision
                data["confidence"] = 0.0
                data["reasoning"] = "unknown_vote"
            return data
        except json.JSONDecodeError:
            logger.warning("parliament_json_parse_failed", response_length=len(text))
            return {"vote": "abstain", "confidence": 0.0, "reasoning": "parse_error"}


# Module-level singleton
llm_gateway = LLMGateway()
