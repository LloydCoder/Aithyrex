"""Deterministic sequence correlation over signed, bounded event metadata.

This module reports patterns; it never authorizes or blocks an action.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Sequence

EventType = Literal[
    "prompt_injection_detected",
    "credential_exposure_detected",
    "sensitive_data_accessed",
    "external_transfer_requested",
    "tool_action_proposed",
    "tool_action_executed",
    "policy_denied",
    "approval_recorded",
]


@dataclass(frozen=True)
class BehaviorEvent:
    event_id: str
    event_type: EventType
    occurred_at: datetime
    tool_name: str | None = None


@dataclass(frozen=True)
class CorrelationFinding:
    rule_id: str
    severity: Literal["medium", "high", "critical"]
    first_event_id: str
    second_event_id: str
    window_seconds: int
    description: str
    confidence_calibrated: bool = False


def correlate_events(events: Sequence[BehaviorEvent]) -> list[CorrelationFinding]:
    """Find explicit event sequences within bounded time windows.

    Input must already be validated and ordered. Findings are advisory signals,
    not proof of malicious intent and not authorization decisions.
    """
    findings: list[CorrelationFinding] = []
    for index, first in enumerate(events):
        for second in events[index + 1:]:
            elapsed = int((second.occurred_at - first.occurred_at).total_seconds())
            if elapsed < 0:
                continue
            if elapsed > 3600:
                break

            rule: tuple[str, str] | None = None
            if (
                first.event_type == "credential_exposure_detected"
                and second.event_type == "external_transfer_requested"
                and elapsed <= 600
            ):
                rule = ("credential_exposure_then_external_transfer", "critical")
            elif (
                first.event_type == "prompt_injection_detected"
                and second.event_type in {"external_transfer_requested", "tool_action_executed"}
                and elapsed <= 600
            ):
                rule = ("injection_then_external_action", "high")
            elif (
                first.event_type == "sensitive_data_accessed"
                and second.event_type == "external_transfer_requested"
                and elapsed <= 600
            ):
                rule = ("sensitive_access_then_external_transfer", "high")
            elif (
                first.event_type == "policy_denied"
                and second.event_type == "tool_action_proposed"
                and first.tool_name
                and first.tool_name == second.tool_name
                and elapsed <= 300
            ):
                rule = ("denied_action_retried", "medium")

            if rule is not None:
                rule_id, severity = rule
                findings.append(
                    CorrelationFinding(
                        rule_id=rule_id,
                        severity=severity,  # type: ignore[arg-type]
                        first_event_id=first.event_id,
                        second_event_id=second.event_id,
                        window_seconds=elapsed,
                        description=_DESCRIPTIONS[rule_id],
                    )
                )
    return findings


_DESCRIPTIONS = {
    "credential_exposure_then_external_transfer":
        "A credential-exposure signal preceded an external-transfer request within ten minutes.",
    "injection_then_external_action":
        "A prompt-injection signal preceded an external action within ten minutes.",
    "sensitive_access_then_external_transfer":
        "A sensitive-data access signal preceded an external-transfer request within ten minutes.",
    "denied_action_retried":
        "A tool action was proposed again after a prior denial within five minutes.",
}
