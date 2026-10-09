"""
AI Shield — Covert Channel Detector
=====================================
Detects steganographic and encoding-based covert channels
in LLM completions using ThreatFade's entropy/Z-score methodology.

ThreatFade provides a supplementary signal. Network-traffic results do not
validate AI-text detection accuracy; this detector's thresholds require a
separate representative AI-interaction evaluation.

Anomalous entropy patterns in completions indicate:
  - Data exfiltration via whitespace/Unicode steganography
  - Base64/hex-encoded payloads embedded in natural language
  - Timing-channel patterns in streaming responses
  - Unusual character distribution consistent with encoded data

MITRE ATLAS: AML.T0048 — Exfiltration via ML Inference API
Sprint 1: ThreatFade HTTP bridge + basic encoding detection.
Sprint 2: Full token distribution Z-score analysis.
"""

from __future__ import annotations

import re

import structlog

from backend.core.shield_engine import DetectionResult, Severity
from backend.core.threatfade_client import threatfade

logger = structlog.get_logger(__name__)

# ── Encoding detection patterns ───────────────────────────────────────
_BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_PATTERN    = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_UNICODE_DENSE  = re.compile(r"[\u200b-\u200f\u202a-\u202e\ufeff]{3,}")  # zero-width chars


class CovertChannelDetector:
    """
    Detects covert channel patterns in LLM output.

    Pipeline:
      1. Fast regex scan for obvious encoding patterns
      2. ThreatFade entropy analysis on the full completion
      3. Z-score comparison against clean completion baseline

    Sprint 1: steps 1 + 2.
    Sprint 2: step 3 with rolling baseline per tenant.
    """

    async def detect(
        self,
        prompt: str,
        completion: str | None = None,
    ) -> DetectionResult:
        """
        Scan LLM completion for covert channel indicators.

        Completions are the primary target — this is where
        exfiltration or C2 signalling would appear.
        """
        if not completion:
            return DetectionResult(
                detector="covert_channel",
                detected=False,
                severity=Severity.CLEAN,
                confidence=0.0,
                details={"reason": "no_completion"},
            )

        indicators = []

        # ── Step 1: Fast encoding scan ────────────────────────────────
        if _BASE64_PATTERN.search(completion):
            indicators.append("base64_blob")
        if _HEX_PATTERN.search(completion):
            indicators.append("hex_blob")
        if _UNICODE_DENSE.search(completion):
            indicators.append("zero_width_steganography")

        # ── Step 2: ThreatFade entropy analysis ───────────────────────
        tf_result = await threatfade.detect(completion, source="llm_completion")
        tf_detected = tf_result.get("detected", False)
        tf_confidence = tf_result.get("confidence", "info")
        z_outlier = tf_result.get("z_outlier", 0.0)

        if tf_detected:
            indicators.append(f"threatfade_c2_entropy (z={z_outlier:.2f})")

        if not indicators:
            degraded = bool(tf_result.get("degraded") or tf_result.get("fallback"))
            return DetectionResult(
                detector="covert_channel",
                detected=False,
                severity=Severity.CLEAN,
                confidence=0.0,
                details={
                    "degraded": degraded,
                    "reason": "threatfade_unavailable" if degraded else "no_indicators",
                    "z_outlier": z_outlier,
                },
            )

        # Z-score above 10 → CRITICAL (ThreatFade baseline: 14.76 on real malware)
        if z_outlier >= 10.0:
            severity = Severity.CRITICAL
            confidence = 0.95
        elif z_outlier >= 5.0 or len(indicators) >= 2:
            severity = Severity.HIGH
            confidence = 0.80
        else:
            severity = Severity.MEDIUM
            confidence = 0.55

        logger.warning(
            "covert_channel_detected",
            indicators=indicators,
            z_outlier=z_outlier,
            severity=severity,
        )

        return DetectionResult(
            detector="covert_channel",
            detected=True,
            severity=severity,
            confidence=confidence,
            details={
                "indicators": indicators,
                "z_outlier": z_outlier,
                "threatfade_confidence": tf_confidence,
                "degraded": bool(tf_result.get("degraded") or tf_result.get("fallback")),
            },
            mitre_atlas=["AML.T0048", "T1027"],
        )
