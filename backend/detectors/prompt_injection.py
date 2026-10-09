"""
Aithyrex — Prompt Injection Detector
=======================================
Detects direct and indirect prompt injection attacks.

Direct injection:  User input attempts to override system prompt.
Indirect injection: Malicious content in retrieved docs / tool outputs
                    that gets fed to the model (RAG poisoning).

Sprint 1: implement direct injection pattern matching.
Sprint 2: add semantic embedding-based detection for indirect injection.

MITRE ATLAS: AML.T0051 — LLM Prompt Injection
"""

from __future__ import annotations

import re

import structlog

from backend.core.shield_engine import DetectionResult, Severity

logger = structlog.get_logger(__name__)

# ── Direct injection patterns ─────────────────────────────────────────
# Compiled at module load — never inside the hot path
_DIRECT_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
        r"disregard\s+(your\s+)?(previous|prior|system)\s+(prompt|instructions?)",
        r"you\s+are\s+now\s+(a\s+)?(?!an?\s+AI|an?\s+assistant)",
        r"act\s+as\s+(if\s+you\s+(are|were)\s+)?(?!an?\s+AI|an?\s+assistant)",
        r"new\s+persona[:\s]",
        r"system\s*:\s*you\s+are",
        r"<\s*system\s*>",
        r"\[system\]",
        r"jailbreak",
        r"DAN\s+mode",
        r"developer\s+mode\s+(enabled|on|activated)",
    ]
]


class PromptInjectionDetector:
    """
    Detects prompt injection attempts in LLM inputs.

    Sprint 1 implementation: regex-based direct injection detection.
    Sprint 2: semantic similarity against injection corpus.
    Sprint 3: indirect injection via retrieved context scanning.
    """

    async def detect(
        self,
        prompt: str,
        completion: str | None = None,
    ) -> DetectionResult:
        """
        Scan prompt for injection indicators.

        Args:
            prompt:     The input to scan.
            completion: Not used for injection detection (input-side only).

        Returns:
            DetectionResult with severity and matched patterns.
        """
        matches = []
        for pattern in _DIRECT_PATTERNS:
            m = pattern.search(prompt)
            if m:
                matches.append(m.group(0))

        if not matches:
            return DetectionResult(
                detector="prompt_injection",
                detected=False,
                severity=Severity.CLEAN,
                confidence=0.0,
            )

        # Severity scales with number of matched patterns
        confidence = min(1.0, len(matches) * 0.4)
        severity = Severity.HIGH if len(matches) >= 2 else Severity.MEDIUM

        logger.warning(
            "prompt_injection_detected",
            matches=matches,
            severity=severity,
            confidence=confidence,
        )

        return DetectionResult(
            detector="prompt_injection",
            detected=True,
            severity=severity,
            confidence=confidence,
            details={"matched_patterns": matches, "match_count": len(matches)},
            mitre_atlas=["AML.T0051"],
        )
