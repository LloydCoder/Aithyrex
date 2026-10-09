"""
AI Shield — LangChain Integration (PyPI package)
==================================================
Usage:
    from ai_shield.integrations.langchain import AIShieldCallback
    from langchain_anthropic import ChatAnthropic

    llm = ChatAnthropic(callbacks=[AIShieldCallback(api_key="your-key")])
"""

from __future__ import annotations
from typing import Any
from ai_shield.client import Shield


class AIShieldCallback:
    """
    LangChain callback handler for AI Shield.
    Drop into any LangChain LLM, chain, or agent.
    """

    def __init__(
        self,
        api_key: str = "",
        base_url: str = "https://api.aishield.tinlance.com",
        raise_on_block: bool = True,
    ) -> None:
        self._shield = Shield(api_key=api_key, base_url=base_url)
        self._raise = raise_on_block
        self._last_prompt = ""

    def on_llm_start(self, serialized: dict, prompts: list[str], **kwargs: Any) -> None:
        for prompt in prompts:
            self._last_prompt = prompt
            verdict = self._shield.inspect_sync(prompt=prompt)
            if verdict.blocked and self._raise:
                raise PermissionError(
                    f"[AI Shield] LangChain prompt blocked. Severity: {verdict.severity}."
                )

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        try:
            text = response.generations[0][0].text
            if text and self._last_prompt:
                verdict = self._shield.inspect_sync(
                    prompt=self._last_prompt, completion=text
                )
                if verdict.blocked and self._raise:
                    raise PermissionError(
                        f"[AI Shield] LangChain completion blocked. Severity: {verdict.severity}."
                    )
        except (AttributeError, IndexError):
            pass

    def on_llm_error(self, error: Exception, **kwargs: Any) -> None:
        pass

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs: Any) -> None:
        verdict = self._shield.inspect_sync(prompt=input_str)
        if verdict.blocked and self._raise:
            raise PermissionError(
                f"[AI Shield] Tool input blocked. Severity: {verdict.severity}."
            )

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        verdict = self._shield.inspect_sync(prompt="", completion=output)
        if verdict.blocked and self._raise:
            raise PermissionError(
                f"[AI Shield] Tool output blocked. Severity: {verdict.severity}."
            )

    def on_agent_action(self, action: Any, **kwargs: Any) -> None:
        pass

    def on_agent_finish(self, finish: Any, **kwargs: Any) -> None:
        pass
