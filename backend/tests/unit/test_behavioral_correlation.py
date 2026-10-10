"""Deterministic tests for multi-event behavioral correlation."""
from datetime import datetime, timedelta, timezone

from backend.core.behavioral_correlation import BehaviorEvent, correlate_events

BASE = datetime(2026, 10, 10, 10, 0, tzinfo=timezone.utc)


def event(event_id, event_type, seconds=0, tool_name=None):
    return BehaviorEvent(
        event_id=event_id,
        event_type=event_type,
        occurred_at=BASE + timedelta(seconds=seconds),
        tool_name=tool_name,
    )


def test_credential_exposure_then_transfer_is_critical():
    findings = correlate_events([
        event("e1", "credential_exposure_detected"),
        event("e2", "external_transfer_requested", 120),
    ])
    assert len(findings) == 1
    assert findings[0].rule_id == "credential_exposure_then_external_transfer"
    assert findings[0].severity == "critical"
    assert findings[0].window_seconds == 120
    assert findings[0].confidence_calibrated is False


def test_prompt_injection_then_tool_execution_is_high():
    findings = correlate_events([
        event("e1", "prompt_injection_detected"),
        event("e2", "tool_action_executed", 30, "send_email"),
    ])
    assert [item.rule_id for item in findings] == ["injection_then_external_action"]


def test_sensitive_access_then_external_transfer_is_high():
    findings = correlate_events([
        event("e1", "sensitive_data_accessed"),
        event("e2", "external_transfer_requested", 60),
    ])
    assert [item.rule_id for item in findings] == ["sensitive_access_then_external_transfer"]


def test_denied_action_retry_requires_same_tool_and_short_window():
    matched = correlate_events([
        event("e1", "policy_denied", tool_name="send_email"),
        event("e2", "tool_action_proposed", 180, "send_email"),
    ])
    unmatched = correlate_events([
        event("e1", "policy_denied", tool_name="send_email"),
        event("e2", "tool_action_proposed", 180, "read_file"),
    ])
    assert [item.rule_id for item in matched] == ["denied_action_retried"]
    assert unmatched == []


def test_isolated_signals_and_events_outside_window_do_not_correlate():
    assert correlate_events([event("e1", "prompt_injection_detected")]) == []
    assert correlate_events([
        event("e1", "prompt_injection_detected"),
        event("e2", "external_transfer_requested", 601),
    ]) == []


def test_sequence_rules_do_not_emit_for_reversed_event_order():
    # The route rejects out-of-order timestamps; the pure evaluator also avoids
    # correlating a later event with an earlier index that has a negative delta.
    findings = correlate_events([
        event("e1", "external_transfer_requested"),
        event("e2", "credential_exposure_detected", 30),
    ])
    assert findings == []
