"""
AI Shield — LlamaIndex Integration
=====================================
Observer/callback for LlamaIndex query pipelines.
Monitors every LLM call, retrieval, and tool invocation.

Usage:
    # Server-side (backend integration)
    from backend.integrations.llamaindex_middleware import AIShieldObserver
    observer = AIShieldObserver()
    Settings.callback_manager = CallbackManager([observer])

    # PyPI package (lightweight HTTP)
    from ai_shield.integrations.llamaindex import AIShieldObserver
    observer = AIShieldObserver(api_key="your-key")
"""

from __future__ import annotations

from typing import Any, Optional

import structlog

logger = structlog.get_logger(__name__)


class AIShieldObserver:
    """
    LlamaIndex callback/observer for AI Shield.

    Hooks into LlamaIndex's CallbackManager to inspect:
      - LLM inputs and outputs
      - Retrieved context (RAG poisoning detection)
      - Tool/function call inputs and outputs
      - Agent step inputs and outputs

    Sprint 1: logging only.
    Sprint 2: full ShieldEngine integration.
    """

    def __init__(
        self,
        api_key: str = "",
        base_url: str = "https://api.aishield.tinlance.com",
        tenant_id: str = "",
        plan: str = "free",
        raise_on_block: bool = True,
    ) -> None:
        self._api_key     = api_key
        self._base_url    = base_url
        self._tenant_id   = tenant_id
        self._plan        = plan
        self._raise       = raise_on_block
        self._last_prompt = ""
        logger.info("llamaindex_observer_active", tenant_id=tenant_id)

    # ── LLM events ────────────────────────────────────────────────────────────
    def on_llm_start(
        self,
        serialized: dict,
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Called before LLM processes input."""
        for prompt in prompts:
            self._last_prompt = prompt
            self._inspect_sync(prompt=prompt, source="llm_input")

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Called after LLM returns output — scan completion."""
        try:
            # LlamaIndex response structure
            text = ""
            if hasattr(response, "text"):
                text = response.text
            elif hasattr(response, "generations"):
                text = response.generations[0][0].text if response.generations else ""

            if text and self._last_prompt:
                self._inspect_sync(
                    prompt=self._last_prompt,
                    completion=text,
                    source="llm_output",
                )
        except Exception as e:
            logger.warning("llamaindex_end_inspect_failed", error=str(e))

    # ── Retrieval events ──────────────────────────────────────────────────────
    def on_retrieve(self, nodes: list, **kwargs: Any) -> None:
        """
        Called after retrieval — scan retrieved documents for RAG poisoning.
        This is where indirect injection most commonly enters the pipeline.
        """
        for node in nodes:
            try:
                text = node.get_text() if hasattr(node, "get_text") else str(node)
                if text:
                    self._inspect_sync(prompt=text, source="retrieved_context")
            except Exception as e:
                logger.warning("llamaindex_retrieve_inspect_failed", error=str(e))

    # ── Tool events ────────────────────────────────────────────────────────────
    def on_tool_start(
        self,
        serialized: dict,
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Called before a tool executes — inspect tool input."""
        self._inspect_sync(prompt=input_str, source="tool_input")

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Called after tool returns — inspect tool output for injection."""
        self._inspect_sync(prompt="", completion=output, source="tool_output")

    # ── Agent events ──────────────────────────────────────────────────────────
    def on_agent_step(self, step: Any, **kwargs: Any) -> None:
        """Called at each agent reasoning step."""
        logger.info(
            "llamaindex_agent_step",
            step_type=type(step).__name__,
            tenant_id=self._tenant_id,
        )

    # ── Internal ──────────────────────────────────────────────────────────────
    def _inspect_sync(
        self,
        prompt: str,
        completion: Optional[str] = None,
        source: str = "unknown",
    ) -> None:
        """
        Synchronous inspection via AI Shield API.
        Raises PermissionError if blocked and raise_on_block=True.
        """
        if self._api_key:
            # Use PyPI HTTP client when API key is set
            try:
                from ai_shield.client import Shield
                shield = Shield(api_key=self._api_key, base_url=self._base_url)
                verdict = shield.inspect_sync(prompt=prompt, completion=completion)
                if verdict.blocked and self._raise:
                    raise PermissionError(
                        f"[AI Shield] LlamaIndex {source} blocked. "
                        f"Severity: {verdict.severity}."
                    )
                logger.info(
                    "llamaindex_inspect",
                    source=source,
                    action=verdict.action,
                    severity=verdict.severity,
                )
            except PermissionError:
                raise
            except Exception as e:
                logger.error("llamaindex_inspect_failed", error=str(e), source=source)
        else:
            # Server-side: use ShieldEngine directly
            import asyncio
            try:
                from backend.core.shield_engine import ShieldEngine, Action
                engine = ShieldEngine()
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(engine.inspect(
                        prompt=prompt,
                        completion=completion,
                        tenant_id=self._tenant_id,
                        plan=self._plan,
                    ))
                else:
                    verdict = loop.run_until_complete(engine.inspect(
                        prompt=prompt,
                        completion=completion,
                        tenant_id=self._tenant_id,
                        plan=self._plan,
                    ))
                    if verdict.blocked and self._raise:
                        raise PermissionError(
                            f"[AI Shield] LlamaIndex {source} blocked."
                        )
            except PermissionError:
                raise
            except Exception as e:
                logger.warning("llamaindex_local_inspect_failed", error=str(e))
