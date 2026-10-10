"""Unit tests for deterministic context-bundle canonicalization."""
from backend.core.platform_context_auth import canonical_context_bundle_bytes, context_bundle_sha256


def test_context_bundle_canonicalization_sorts_mapping_keys():
    first = [{"source_type": "tool_output", "source_id": "tool-1", "content": "value"}]
    second = [{"content": "value", "source_id": "tool-1", "source_type": "tool_output"}]
    assert canonical_context_bundle_bytes("agent-1", "context-1", first) == canonical_context_bundle_bytes(
        "agent-1", "context-1", second
    )


def test_context_bundle_hash_changes_when_content_changes():
    original = [{"source_type": "memory", "source_id": "mem-1", "content": "original"}]
    changed = [{"source_type": "memory", "source_id": "mem-1", "content": "changed"}]
    assert context_bundle_sha256("agent-1", "context-1", original) != context_bundle_sha256(
        "agent-1", "context-1", changed
    )


def test_context_bundle_hash_changes_when_source_changes():
    original = [{"source_type": "memory", "source_id": "mem-1", "content": "same"}]
    changed = [{"source_type": "tool_output", "source_id": "mem-1", "content": "same"}]
    assert context_bundle_sha256("agent-1", "context-1", original) != context_bundle_sha256(
        "agent-1", "context-1", changed
    )
