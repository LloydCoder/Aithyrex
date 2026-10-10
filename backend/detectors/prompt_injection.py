"""Rule-based prompt-injection indicators with bounded, privacy-safe inspection.

This detector is a deterministic heuristic, not a semantic classifier. It reports
rule identifiers rather than matched customer text, and it never claims calibrated
probability. Source-aware RAG/tool-output lineage remains a separate control.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

import structlog

from backend.core.shield_engine import DetectionResult, Severity

logger = structlog.get_logger(__name__)

MAX_SCAN_CHARS = 200_000
MAX_ENCODED_CANDIDATES = 32
MAX_DECODED_BYTES = 4_096
_ZERO_WIDTH_AND_BIDI = dict.fromkeys(
    map(ord, "\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\ufeff"),
    None,
)

# Stable rule IDs are evidence metadata. Never put raw matched prompt fragments in logs.
_DIRECT_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ignore_previous_instructions", re.compile(r"ignore\\s+(all\\s+)?(previous|prior|above)\\s+instructions?", re.IGNORECASE)),
    ("disregard_system_prompt", re.compile(r"disregard\\s+(your\\s+)?(previous|prior|system)\\s+(prompt|instructions?)", re.IGNORECASE)),
    ("persona_override", re.compile(r"you\\s+are\\s+now\\s+(a\\s+)?(?!an?\\s+AI|an?\\s+assistant)", re.IGNORECASE)),
    ("roleplay_override", re.compile(r"act\\s+as\\s+(if\\s+you\\s+(are|were)\\s+)?(?!an?\\s+AI|an?\\s+assistant)", re.IGNORECASE)),
    ("new_persona", re.compile(r"new\\s+persona[:\\s]", re.IGNORECASE)),
    ("system_tag", re.compile(r"<\\s*system\\s*>|\\[system\\]", re.IGNORECASE)),
    ("jailbreak_keyword", re.compile(r"\\bjailbreak\\b", re.IGNORECASE)),
    ("dan_mode", re.compile(r"\\bDAN\\s+mode\\b", re.IGNORECASE)),
    ("developer_mode_override", re.compile(r"developer\\s+mode\\s+(enabled|on|activated)", re.IGNORECASE)),
    ("reveal_hidden_prompt", re.compile(r"(reveal|show|print|repeat|expose|dump)\\s+(the\\s+)?(hidden\\s+|system\\s+|developer\\s+)?(prompt|instructions?|messages?)", re.IGNORECASE)),
    ("disable_safety_controls", re.compile(r"(bypass|ignore|disable|override)\\s+(all\\s+)?(safety|content|security)\\s+(rules?|filters?|polic(?:y|ies)|guardrails?)", re.IGNORECASE)),
    ("exfiltrate_credentials", re.compile(r"(send|exfiltrate|upload|forward|reveal)\\s+(all\\s+)?(secrets?|credentials?|api\\s+keys?|tokens?)", re.IGNORECASE)),
]
_BASE64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,4096}={0,2}(?![A-Za-z0-9+/])")
_HEX_CANDIDATE = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{48,8192}(?![0-9A-Fa-f])")


def _normalize(text: str) -> str:
    """Normalize common compatibility and invisible-control obfuscation."""
    return unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH_AND_BIDI)


def _has_direct_indicator(text: str) -> bool:
    return any(pattern.search(text) for _, pattern in _DIRECT_PATTERNS)


def _encoded_instruction_ids(text: str) -> list[str]:
    """Decode only small, bounded candidate blobs and return IDs, never decoded content."""
    found: list[str] = []
    inspected = 0
    for match in _BASE64_CANDIDATE.finditer(text):
        if inspected >= MAX_ENCODED_CANDIDATES:
            break
        inspected += 1
        candidate = match.group(0)
        try:
            padded = candidate + ("=" * (-len(candidate) % 4))
            decoded = base64.b64decode(padded, validate=True)
            if len(decoded) <= MAX_DECODED_BYTES:
                text_value = _normalize(decoded.decode("utf-8", errors="ignore"))
                if text_value and _has_direct_indicator(text_value):
                    found.append("encoded_base64_instruction")
        except (binascii.Error, ValueError):
            continue

    for match in _HEX_CANDIDATE.finditer(text):
        if inspected >= MAX_ENCODED_CANDIDATES:
            break
        inspected += 1
        try:
            decoded = bytes.fromhex(match.group(0))
            if len(decoded) <= MAX_DECODED_BYTES:
                text_value = _normalize(decoded.decode("utf-8", errors="ignore"))
                if text_value and _has_direct_indicator(text_value):
                    found.append("encoded_hex_instruction")
        except ValueError:
            continue
    return found


class PromptInjectionDetector:
    """Detect direct rule indicators and bounded base64/hex-encoded instructions.

    Indirect-injection text can be flagged when it appears in the scanned input,
    but this detector does not identify trust boundaries or establish whether
    retrieved/tool content was authorized. Those require structured provenance.
    """

    async def detect(
        self,
        prompt: str,
        completion: str | None = None,
    ) -> DetectionResult:
        """Inspect prompt text without logging or returning raw matched content."""
        if len(prompt) > MAX_SCAN_CHARS:
            return DetectionResult(
                detector="prompt_injection",
                detected=False,
                severity=Severity.INFO,
                confidence=0.0,
                details={
                    "degraded": True,
                    "reason": "input_exceeds_scan_limit",
                    "scan_limit": MAX_SCAN_CHARS,
                    "confidence_calibrated": False,
                },
            )

        normalized = _normalize(prompt)
        matches = [
            rule_id for rule_id, pattern in _DIRECT_PATTERNS
            if pattern.search(normalized)
        ]
        matches.extend(_encoded_instruction_ids(normalized))
        # Preserve stable ordering while avoiding duplicate evidence IDs.
        matches = list(dict.fromkeys(matches))

        if not matches:
            return DetectionResult(
                detector="prompt_injection",
                detected=False,
                severity=Severity.CLEAN,
                confidence=0.0,
                details={"confidence_calibrated": False, "match_count": 0},
            )

        severity = Severity.HIGH if len(matches) >= 2 else Severity.MEDIUM
        logger.warning(
            "prompt_injection_detected",
            matched_rule_ids=matches,
            severity=severity,
            confidence_calibrated=False,
        )

        return DetectionResult(
            detector="prompt_injection",
            detected=True,
            severity=severity,
            confidence=0.0,
            details={
                "matched_patterns": matches,
                "match_count": len(matches),
                "confidence_calibrated": False,
            },
            mitre_atlas=["AML.T0051"],
        )
