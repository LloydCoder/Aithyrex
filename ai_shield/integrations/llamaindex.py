"""
AI Shield — LlamaIndex Integration (PyPI package)
===================================================
Usage:
    from ai_shield.integrations.llamaindex import AIShieldObserver
    from llama_index.core import Settings
    from llama_index.core.callbacks import CallbackManager

    observer = AIShieldObserver(api_key="your-key")
    Settings.callback_manager = CallbackManager([observer])
    # All LlamaIndex LLM + retrieval calls now monitored
"""

from __future__ import annotations
from typing import Any, Optional
from ai_shield.client import Shield


class AIShieldObserver:
    """LlamaIndex callback handler for AI Shield monitoring."""

    def __init__(
        self,
        api_key: str = "",
        base_url: str = "https://api.aishield.tinlance.com",
        raise_on_block: bool = True,
    ) -> None:
        self._shield = Shield(api_key=api_key, base_url=base_url)
        self._raise  = raise_on_block
        self._last_prompt = ""

    def on_llm_start(self, serialized: dict, prompts: list[str], **kwargs: Any) -> None:
        for prompt in prompts:
            self._last_prompt = prompt
            self._check(prompt=prompt)

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        try:
            text = getattr(response, "text", None) or ""
            if text and self._last_prompt:
                self._check(prompt=self._last_prompt, completion=text)
        except Exception:
            pass

    def on_retrieve(self, nodes: list, **kwargs: Any) -> None:
        """Scan retrieved nodes for RAG poisoning."""
        for node in nodes:
            try:
                text = node.get_text() if hasattr(node, "get_text") else str(node)
                if text:
                    self._check(prompt=text[:2000])
            except Exception:
                pass

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs: Any) -> None:
        self._check(prompt=input_str)

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        self._check(prompt="", completion=output)

    def _check(self, prompt: str, completion: Optional[str] = None) -> None:
        verdict = self._shield.inspect_sync(prompt=prompt, completion=completion)
        if verdict.blocked and self._raise:
            raise PermissionError(
                f"[AI Shield] LlamaIndex blocked. Severity: {verdict.severity}."
            )
