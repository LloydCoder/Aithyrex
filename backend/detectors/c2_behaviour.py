"""
Aithyrex — C2 Behaviour Detector
====================================
Flags C2-like signals in supported AI interactions for triage; AI-text effectiveness is not validated.

Uses ThreatFade as a supplementary signal. Historical network-traffic
metrics do not validate AI-text detection accuracy; thresholds require
separate representative AI-interaction evaluation.

In agentic AI, C2 indicators include:
  - Regular heartbeat-like API polling patterns
  - Encoded instructions hidden in benign-looking completions
  - Out-of-distribution token sequences consistent with C2 beaconing
  - Domain generation algorithm (DGA) patterns in tool call arguments

MITRE ATT&CK: T1071.001 — C2 via Web Protocols
MITRE ATT&CK: T1095    — Non-Application Layer Protocol
MITRE ATLAS:  AML.T0043 — Craft Adversarial Data
"""

from __future__ import annotations

import structlog

from backend.core.shield_engine import DetectionResult, Severity
from backend.core.threatfade_client import threatfade

logger = structlog.get_logger(__name__)


class C2BehaviourDetector:
    """
    Flags C2-like behavior heuristically; it is not a validated AI-text C2 detector.

    Primary method: ThreatFade HTTP bridge.
    Supplementary: behavioural heuristics for agent traffic.

    Sprint 1: ThreatFade bridge only.
    Sprint 2: Agent communication graph analysis via ReconOS OFE.
    """

    async def detect(
        self,
        prompt: str,
        completion: str | None = None,
    ) -> DetectionResult:
        """Submit both prompt and completion to ThreatFade for C2 analysis."""
        text = prompt + (" " + completion if completion else "")

        tf_result = await threatfade.detect(text, source="ai_traffic_c2")
        detected = tf_result.get("detected", False)
        z_outlier = tf_result.get("z_outlier", 0.0)
        mitre_ttp = tf_result.get("mitre_ttp", "")
        degraded = bool(tf_result.get("degraded") or tf_result.get("fallback"))

        if degraded:
            return DetectionResult(
                detector="c2_behaviour",
                detected=False,
                severity=Severity.INFO,
                confidence=0.0,
                details={"z_outlier": z_outlier, "degraded": True, "reason": "threatfade_unavailable"},
            )

        if not detected:
            return DetectionResult(
                detector="c2_behaviour",
                detected=False,
                severity=Severity.CLEAN,
                confidence=0.0,
                details={
                    "z_outlier": z_outlier,
                    "degraded": bool(tf_result.get("degraded") or tf_result.get("fallback")),
                    "reason": "threatfade_unavailable" if tf_result.get("degraded") or tf_result.get("fallback") else "no_indicators",
                },
            )

        # ThreatFade scores are not validated for AI text. Keep this detector advisory-only.
        severity = Severity.MEDIUM
        confidence = 0.0

        logger.warning(
            "c2_behaviour_detected",
            z_outlier=z_outlier,
            severity=severity,
            mitre_ttp=mitre_ttp,
        )

        return DetectionResult(
            detector="c2_behaviour",
            detected=True,
            severity=severity,
            confidence=confidence,
            details={
                "z_outlier": z_outlier,
                "mitre_ttp": mitre_ttp,
                "score": tf_result.get("score"),
                "entropy": tf_result.get("entropy"),
                "rules_matched": tf_result.get("rules_matched"),
                "degraded": False,
                "confidence_calibrated": False,
            },
            mitre_atlas=[mitre_ttp, "T1071.001", "T1095"],
        )
