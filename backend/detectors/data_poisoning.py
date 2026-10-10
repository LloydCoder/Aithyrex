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

# Stable rule IDs stay separate from the regex implementation and matched content.
_RAG_RULE_IDS = [
    "rag_attention_ai", "rag_note_to_ai", "rag_system_override",
    "rag_ai_ignore_instruction", "rag_instructions_cancelled", "rag_new_task",
    "rag_from_now_on", "rag_inject_marker", "rag_override_marker", "rag_html_ai_instruction",
]
_EXTRACTION_RULE_IDS = [
    "extract_repeat_system_prompt", "extract_initial_original_prompt",
    "extract_training_internal_data", "extract_training_data_query",
    "extract_training_text_reproduction", "extract_recite_prompt",
    "extract_show_system_prompt", "extract_confidential_instructions",
    "extract_exact_instructions", "extract_copy_system_prompt",
]
_TOOL_RULE_IDS = [
    "tool_result_instruction", "function_output_instruction",
    "api_response_instruction", "search_result_instruction",
]

# Context overflow — repetition attacks
_OVERFLOW_CHUNK_SIZE = 20

# Suspicious tool output injection markers
_TOOL_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"<tool_result>.*?(ignore|override|disregard)",
        r"<function_output>.*?(system|instruction)",
        r"API\s+RESPONSE.*?(ignore|override|new\s+task)",
        r"SEARCH\s+RESULT.*?(you\s+are\s+now|your\s+new)",
    ]
]


def _check_context_overflow(text: str) -> tuple[bool, int]:
    """
    Detect repetition-based context overflow attacks.
    Attackers flood the context with repeated content to push
    the system prompt out of the model's effective context window.
    """
    if len(text) < 500:
        return False, 0

    # Sample chunks across the text and count repeats
    chunks: dict[str, int] = {}
    for i in range(0, len(text) - _OVERFLOW_CHUNK_SIZE, _OVERFLOW_CHUNK_SIZE // 2):
        chunk = text[i:i + _OVERFLOW_CHUNK_SIZE].lower().strip()
        if len(chunk) >= 10:
            chunks[chunk] = chunks.get(chunk, 0) + 1

    max_repeats = max(chunks.values()) if chunks else 0
    if max_repeats >= _OVERFLOW_REPEAT_THRESHOLD:
        return True, max_repeats

    return False, max_repeats


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
        for rule_id, pattern in zip(_RAG_RULE_IDS, _RAG_POISON_PATTERNS, strict=True):
            if pattern.search(target):
                indicators.append({
                    "type": "rag_poisoning",
                    "rule_id": rule_id,
                    "severity": Severity.HIGH,
                })

        # ── Layer 2: Training data extraction ────────────────────────────
        for rule_id, pattern in zip(_EXTRACTION_RULE_IDS, _EXTRACTION_PATTERNS, strict=True):
            if pattern.search(prompt):   # Extraction attempts are in prompt
                indicators.append({
                    "type": "training_extraction",
                    "rule_id": rule_id,
                    "severity": Severity.MEDIUM,
                })

        # ── Layer 3: Context overflow ─────────────────────────────────────
        overflowed, repeat_count = _check_context_overflow(prompt)
        if overflowed:
            indicators.append({
                "type": "context_overflow",
                "repeat_count": repeat_count,
                "severity": Severity.HIGH,
            })

        # ── Layer 4: Tool output injection ────────────────────────────────
        if completion:
            for rule_id, pattern in zip(_TOOL_RULE_IDS, _TOOL_INJECTION_PATTERNS, strict=True):
                if pattern.search(completion):
                    indicators.append({
                        "type": "tool_output_injection",
                        "rule_id": rule_id,
                        "severity": Severity.HIGH,
                    })

        if not indicators:
            return DetectionResult(
                detector="data_poisoning",
                detected=False,
                severity=Severity.CLEAN,
                confidence=0.0,
                details={"confidence_calibrated": False},
            )

        # Determine highest severity
        severities = [ind["severity"] for ind in indicators]
        top_severity = (
            Severity.CRITICAL if Severity.CRITICAL in severities else
            Severity.HIGH if Severity.HIGH in severities else
            Severity.MEDIUM
        )

        # Rule counts are not calibrated probabilities.
        confidence = 0.0

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
                "confidence_calibrated": False,
            },
            mitre_atlas=["AML.T0020", "AML.T0040", "AML.T0051"],
        )
