"""
AI Shield — Credential Leak Detector
======================================
Scans LLM completions for leaked API keys and credentials.

Pattern set: locally maintained credential-format heuristics.
This repository does not claim that these patterns were merged upstream
or independently peer-reviewed unless supporting evidence is recorded.

Nigerian fintech platforms included:
  Paystack, Flutterwave, Remita, Interswitch

These patterns detect when a compromised or manipulated LLM
reproduces credentials from its context window in its output —
a critical data exfiltration vector in RAG systems.

MITRE ATLAS: AML.T0048 — Exfiltration via ML Inference API
MITRE ATT&CK: T1552 — Unsecured Credentials
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import structlog

from backend.core.shield_engine import DetectionResult, Severity

logger = structlog.get_logger(__name__)


@dataclass
class CredentialPattern:
    name: str
    pattern: re.Pattern
    severity: Severity


# ── 18 credential patterns — FDSE Identity Threat Scanner ─────────────
# Same ruleset shipped in FDSE Toolkit v2.0.0
CREDENTIAL_PATTERNS: list[CredentialPattern] = [
    # ── Cloud providers ──────────────────────────────────────────────
    CredentialPattern("aws_access_key",       re.compile(r"AKIA[0-9A-Z]{16}"),                                          Severity.CRITICAL),
    CredentialPattern("aws_secret_key",       re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),   Severity.CRITICAL),
    CredentialPattern("gcp_service_account",  re.compile(r'"type"\s*:\s*"service_account"'),                            Severity.HIGH),
    CredentialPattern("azure_client_secret",  re.compile(r"(?i)azure.{0,20}secret.{0,20}[0-9a-zA-Z\-_]{32,}"),         Severity.HIGH),

    # ── AI providers ─────────────────────────────────────────────────
    CredentialPattern("anthropic_api_key",    re.compile(r"sk-ant-[a-zA-Z0-9\-_]{40,}"),                                Severity.CRITICAL),
    CredentialPattern("openai_api_key",       re.compile(r"sk-[a-zA-Z0-9]{48}"),                                        Severity.CRITICAL),
    CredentialPattern("huggingface_token",    re.compile(r"hf_[a-zA-Z0-9]{36}"),                                        Severity.HIGH),

    # ── Nigerian fintech (locally maintained format heuristics) ───────
    CredentialPattern("paystack_secret",      re.compile(r"sk_(?:live|test)_[a-zA-Z0-9]{40}"),                          Severity.CRITICAL),
    CredentialPattern("paystack_public",      re.compile(r"pk_(?:live|test)_[a-zA-Z0-9]{32,}"),                          Severity.HIGH),
    CredentialPattern("flutterwave_secret",   re.compile(r"FLWSECK(?:_TEST)?-[a-zA-Z0-9]{32,}"),                        Severity.CRITICAL),
    CredentialPattern("flutterwave_public",   re.compile(r"FLWPUBK(?:_TEST)?-[a-zA-Z0-9]{32,}"),                        Severity.HIGH),
    CredentialPattern("remita_api_key",       re.compile(r"(?i)remita.{0,20}['\"][a-zA-Z0-9]{32,}['\"]"),               Severity.HIGH),
    CredentialPattern("interswitch_client",   re.compile(r"(?i)interswitch.{0,30}['\"][a-zA-Z0-9\-]{36,}['\"]"),        Severity.HIGH),

    # ── Generic high-value patterns ───────────────────────────────────
    CredentialPattern("jwt_token",            re.compile(r"eyJ[a-zA-Z0-9_\-]{20,}\.eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}"), Severity.HIGH),
    CredentialPattern("private_key_pem",      re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),                  Severity.CRITICAL),
    CredentialPattern("github_token",         re.compile(r"gh[pousr]_[a-zA-Z0-9]{30,}"),                                Severity.CRITICAL),
    CredentialPattern("stripe_secret",        re.compile(r"sk_(?:live|test)_[a-zA-Z0-9]{24,}"),                         Severity.CRITICAL),
    CredentialPattern("generic_bearer",       re.compile(r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{40,}"),                        Severity.MEDIUM),
]


class CredentialLeakDetector:
    """
    Scans LLM output for leaked credentials.

    Checks both prompt (to catch injection-via-credential-request)
    and completion (primary exfiltration surface).
    """

    async def detect(
        self,
        prompt: str,
        completion: str | None = None,
    ) -> DetectionResult:
        """Scan prompt and completion for credential patterns."""
        target = (completion or "") + " " + prompt
        found: list[dict] = []

        for cp in CREDENTIAL_PATTERNS:
            match = cp.pattern.search(target)
            if match:
                # Redact matched value before logging
                redacted = "[REDACTED]"
                found.append({
                    "pattern": cp.name,
                    "severity": cp.severity,
                    "redacted_match": redacted,
                    "in": "completion" if completion and cp.pattern.search(completion) else "prompt",
                })

        if not found:
            return DetectionResult(
                detector="credential_leak",
                detected=False,
                severity=Severity.CLEAN,
                confidence=0.0,
                details={"confidence_calibrated": False},
            )

        # Highest severity among matches
        severities = [f["severity"] for f in found]
        top_severity = Severity.CRITICAL if Severity.CRITICAL in severities else \
                       Severity.HIGH if Severity.HIGH in severities else Severity.MEDIUM

        logger.critical(
            "credential_leak_detected",
            count=len(found),
            patterns=[f["pattern"] for f in found],
            severity=top_severity,
        )

        return DetectionResult(
            detector="credential_leak",
            detected=True,
            severity=top_severity,
            confidence=0.0,
            details={"matches": found, "count": len(found), "confidence_calibrated": False},
            mitre_atlas=["AML.T0048", "T1552"],
        )
