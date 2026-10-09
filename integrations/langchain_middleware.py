"""
AI Shield — LangChain Callback Handler
=========================================
Plugs into any LangChain chain or agent as a callback handler.
Automatically inspects every LLM input and output.

Usage:
    from ai_shield.integrations.langchain_middleware import AIShieldCallback
    from langchain_anthropic import ChatAnthropic

    llm = ChatAnthropic(callbacks=[AIShieldCallback()])
    # All LangChain calls now monitored

Sprint 1: Stub with logging.
Sprint 2: Full ShieldEngine integration.
"""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class AIShieldCallback:
    """
    LangChain callback handler for AI Shield monitoring.

    Implements LangChain's BaseCallbackHandler interface.
    Registers on any LLM, chain, or agent.
    """

    def on_llm_start(self, serialized: dict, prompts: list[str], **kwargs: Any) -> None:
        """Called before LLM receives input."""
        for prompt in prompts:
            # TODO Sprint 2: asyncio.run(shield_engine.inspect(prompt=prompt))
            logger.info("langchain_llm_start", prompt_len=len(prompt))

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Called after LLM returns output."""
        # TODO Sprint 2: inspect completion
        logger.info("langchain_llm_end")

    def on_llm_error(self, error: Exception, **kwargs: Any) -> None:
        logger.error("langchain_llm_error", error=str(error))

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs: Any) -> None:
        """Called before a tool executes — key for agentic monitoring."""
        # TODO Sprint 2: inspect tool inputs for injection
        logger.info("langchain_tool_start", tool=serialized.get("name"), input_len=len(input_str))

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Called after tool returns — scan for exfiltration."""
        # TODO Sprint 2: inspect tool output for credential leaks
        logger.info("langchain_tool_end", output_len=len(output))

    def on_agent_action(self, action: Any, **kwargs: Any) -> None:
        """Called on every agent decision step."""
        logger.info("langchain_agent_action", tool=getattr(action, "tool", "unknown"))

    def on_agent_finish(self, finish: Any, **kwargs: Any) -> None:
        logger.info("langchain_agent_finish")
