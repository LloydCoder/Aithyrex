"""
AI Shield — Data Poisoning Detector
======================================
Detects context poisoning, RAG poisoning, and training
data extraction attempts in LLM inputs and completions.

Scenarios detected:
  1. RAG context poisoning — malicious instructions embedded
     in retrieved documents fed to the model
  2. Context window overflow — padding/repetition attacks
     designed to push system prompt out of context
  3. Training data extraction — prompts fishing for memorised
     training data (PII, credentials, copyrighted content)
  4. Prompt leakage fishing — attempts to extract system prompt
  5. Indirect injection via tool outputs — malicious content
     returned by tools/APIs injected into model context

MITRE ATLAS: AML.T0020 — Poison Training Data
MITRE ATLAS: AML.T0040 — ML Model Inference API Access
MITRE ATLAS: AML.T0051 — LLM Prompt Injection (indirect)
"""

from __future__ import annotations

import re

import structlog

from backend.core.shield_engine import DetectionResult, Severity

logger = structlog.get_logger(__name__)

# ── Pattern sets ─────────────────────────────────────────────────────────────

# Context poisoning — instructions hidden in retrieved content
_RAG_POISON_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"ATTENTION\s+(AI|ASSISTANT|SYSTEM)\s*:",
        r"NOTE\s+TO\s+(AI|ASSISTANT|LANGUAGE\s+MODEL)\s*:",
        r"SYSTEM\s+OVERRIDE\s*:",
        r"AI\s*:\s*(ignore|disregard|forget)\s+the",
        r"(previous|prior)\s+instructions\s+(are\s+)?(cancelled|revoked|void)",
        r"your\s+new\s+(task|instructions?|objective)\s+(is|are)",
        r"from\s+now\s+on\s+you\s+(will|must|should)",
        r"\[INJECT\]",
        r"\[OVERRIDE\]",
        r"<!-- AI INSTRUCTION",
    ]
]

# Training data extraction fishing
_EXTRACTION_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"repeat\s+(your\s+)?(system\s+)?prompt",
        r"output\s+(your\s+)?(initial|original|system)\s+prompt",
        r"reveal\s+(your\s+)?(training|system|internal)\s+(data|prompt|instructions?)",
        r"(what\s+(data|information)\s+were\s+you\s+trained|reveal\s+what\s+(data|information).{0,20}trained)",
        r"reproduce\s+(text|content)\s+from\s+your\s+training",
        r"recite\s+(your\s+)?(system|initial)\s+(prompt|instructions?)",
        r"(show|display|print)\s+(me\s+)?(your\s+)?(system\s+prompt|instructions)",
        r"tell\s+me\s+your\s+(confidential|secret|internal)\s+(prompt|instructions?)",
        r"what\s+are\s+your\s+(exact\s+)?(instructions|guidelines|rules)",
        r"copy\s+and\s+paste\s+your\s+system\s+prompt",
    ]
]

# Context overflow — repetition attacks
_OVERFLOW_MIN_REPEAT = 8      # Repeated chunk seen this many times = suspicious
_OVERFLOW_CHUNK_SIZE = 20     # Characters per chunk to check

# Suspicious tool output injection markers
_TOOL_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"<tool_result>.*?(ignore|override|disregard)",
        r"<function_output>.*?(system|instruction)",
        r"API\s+RESPONSE.*?(ignore|override|new\s+task)",
        r"SEARCH\s+RESULT.*?(you\s+are\s+now|your\s+new)",
    ]
]


def _check_context_overflow(text: str) -> tuple[bool, str]:
    """
    Detect repetition-based context overflow attacks.
    Attackers flood the context with repeated content to push
    the system prompt out of the model's effective context window.
    """
    if len(text) < 500:
        return False, ""

    # Sample chunks across the text and count repeats
    chunks: dict[str, int] = {}
    for i in range(0, len(text) - _OVERFLOW_CHUNK_SIZE, _OVERFLOW_CHUNK_SIZE // 2):
        chunk = text[i:i + _OVERFLOW_CHUNK_SIZE].lower().strip()
        if len(chunk) >= 10:
            chunks[chunk] = chunks.get(chunk, 0) + 1

    max_repeats = max(chunks.values()) if chunks else 0
    if max_repeats >= _OVERFLOW_REPEAT_THRESHOLD:
        repeated = max(chunks, key=lambda k: chunks[k])
        return True, f"chunk repeated {max_repeats}x: '{repeated[:30]}...'"

    return False, ""


_OVERFLOW_REPEAT_THRESHOLD = 12


class DataPoisoningDetector:
    """
    Detects data poisoning, RAG poisoning, and training data
    extraction attempts.

    Detection layers:
      1. RAG context poisoning patterns
      2. Training data extraction fishing
      3. Context overflow / repetition attacks
      4. Tool output injection markers
    """

    async def detect(
        self,
        prompt: str,
        completion: str | None = None,
    ) -> DetectionResult:
        """
        Scan prompt and completion for data poisoning indicators.
        """
        indicators: list[dict] = []
        target = prompt + (" " + completion if completion else "")

        # ── Layer 1: RAG context poisoning ───────────────────────────────
        for pattern in _RAG_POISON_PATTERNS:
            match = pattern.search(target)
            if match:
                indicators.append({
                    "type": "rag_poisoning",
                    "pattern": pattern.pattern[:60],
                    "match": match.group(0)[:80],
                    "severity": Severity.HIGH,
                })

        # ── Layer 2: Training data extraction ────────────────────────────
        for pattern in _EXTRACTION_PATTERNS:
            match = pattern.search(prompt)   # Extraction attempts are in prompt
            if match:
                indicators.append({
                    "type": "training_extraction",
                    "pattern": pattern.pattern[:60],
                    "match": match.group(0)[:80],
                    "severity": Severity.MEDIUM,
                })

        # ── Layer 3: Context overflow ─────────────────────────────────────
        overflowed, overflow_detail = _check_context_overflow(prompt)
        if overflowed:
            indicators.append({
                "type": "context_overflow",
                "detail": overflow_detail,
                "severity": Severity.HIGH,
            })

        # ── Layer 4: Tool output injection ────────────────────────────────
        if completion:
            for pattern in _TOOL_INJECTION_PATTERNS:
                match = pattern.search(completion)
                if match:
                    indicators.append({
                        "type": "tool_output_injection",
                        "pattern": pattern.pattern[:60],
                        "match": match.group(0)[:80],
                        "severity": Severity.HIGH,
                    })

        if not indicators:
            return DetectionResult(
                detector="data_poisoning",
                detected=False,
                severity=Severity.CLEAN,
                confidence=0.0,
            )

        # Determine highest severity
        severities = [ind["severity"] for ind in indicators]
        top_severity = (
            Severity.CRITICAL if Severity.CRITICAL in severities else
            Severity.HIGH if Severity.HIGH in severities else
            Severity.MEDIUM
        )

        # Confidence scales with indicator count
        confidence = min(0.95, 0.45 + len(indicators) * 0.15)

        logger.warning(
            "data_poisoning_detected",
            indicator_count=len(indicators),
            types=[i["type"] for i in indicators],
            severity=top_severity,
        )

        return DetectionResult(
            detector="data_poisoning",
            detected=True,
            severity=top_severity,
            confidence=confidence,
            details={
                "indicators": indicators,
                "count": len(indicators),
            },
            mitre_atlas=["AML.T0020", "AML.T0040", "AML.T0051"],
        )
