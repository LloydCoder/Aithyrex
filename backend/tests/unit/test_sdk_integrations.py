from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from ai_shield.integrations.openai import ShieldedOpenAI
from ai_shield.integrations.llamaindex import AIShieldObserver


def test_openai_preflight_block_prevents_provider_call():
    provider = MagicMock()
    shield = MagicMock()
    shield.inspect_sync.return_value = SimpleNamespace(
        blocked=True,
        severity="high",
        detections=[],
    )
    wrapper = ShieldedOpenAI(provider, shield)

    with pytest.raises(PermissionError, match="Prompt blocked"):
        wrapper.chat.completions.create(
            model="test-model",
            messages=[{"role": "user", "content": "unsafe request"}],
        )

    provider.chat.completions.create.assert_not_called()


def test_llamaindex_retrieval_extraction_failure_fails_closed():
    observer = AIShieldObserver(
        api_key="session-token",
        base_url="https://api.example.test",
        raise_on_block=True,
    )

    class BrokenNode:
        def get_text(self):
            raise RuntimeError("private retrieval failure details")

    with pytest.raises(PermissionError, match="could not be inspected"):
        observer.on_retrieve([BrokenNode()])


def test_legacy_autogen_and_crewai_adapters_refuse_unsupported_security_claim():
    from integrations.autogen_middleware import ShieldedConversableAgent, ShieldedCrewTask

    with pytest.raises(NotImplementedError, match="not supported"):
        ShieldedConversableAgent(name="legacy-agent")
    with pytest.raises(NotImplementedError, match="not supported"):
        ShieldedCrewTask(description="legacy-task")
