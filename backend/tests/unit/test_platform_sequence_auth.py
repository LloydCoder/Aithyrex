from backend.core.platform_sequence_auth import canonical_sequence_bytes, sequence_sha256


def test_equivalent_utc_timestamp_spellings_have_same_digest():
    first = [{"event_id": "e1", "event_type": "prompt_injection_detected", "occurred_at": "2026-10-10T10:00:00+00:00"}]
    second = [{"event_id": "e1", "event_type": "prompt_injection_detected", "occurred_at": "2026-10-10T10:00:00Z"}]
    assert canonical_sequence_bytes("agent", "seq", first) == canonical_sequence_bytes("agent", "seq", second)
    assert sequence_sha256("agent", "seq", first) == sequence_sha256("agent", "seq", second)
