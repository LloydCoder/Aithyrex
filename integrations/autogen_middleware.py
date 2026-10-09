"""
AI Shield — AutoGen / CrewAI Middleware
=========================================
Hooks for Microsoft AutoGen and CrewAI multi-agent frameworks.

AutoGen usage:
    from integrations.autogen_middleware import ShieldedConversableAgent
    from autogen import ConversableAgent

    agent = ShieldedConversableAgent(
        name="assistant",
        system_message="You are a helpful assistant.",
        shield_api_key="your-key",
    )

CrewAI usage:
    from integrations.autogen_middleware import ShieldedCrewTask
    from crewai import Task

    task = ShieldedCrewTask(
        description="Analyse the report",
        shield_api_key="your-key",
    )
"""

from __future__ import annotations

from typing import Any, Callable, Optional

import structlog

logger = structlog.get_logger(__name__)


class ShieldedConversableAgent:
    """
    AutoGen ConversableAgent wrapper with AI Shield monitoring.

    Wraps any AutoGen agent to intercept all messages in the
    multi-agent conversation flow.

    Usage:
        agent = ShieldedConversableAgent(
            name="assistant",
            system_message="...",
            shield_api_key="your-shield-key",
            llm_config={"model": "gpt-4o", "api_key": "..."},
        )
        # Use exactly like a standard ConversableAgent
    """

    def __init__(
        self,
        name: str,
        system_message: str = "",
        shield_api_key: str = "",
        shield_base_url: str = "https://api.aishield.tinlance.com",
        tenant_id: str = "",
        plan: str = "free",
        raise_on_block: bool = True,
        **autogen_kwargs: Any,
    ) -> None:
        self.name        = name
        self._api_key    = shield_api_key
        self._base_url   = shield_base_url
        self._tenant_id  = tenant_id
        self._plan       = plan
        self._raise      = raise_on_block

        # Lazily import AutoGen to avoid hard dependency
        try:
            from autogen import ConversableAgent
            self._agent = ConversableAgent(
                name=name,
                system_message=system_message,
                **autogen_kwargs,
            )
        except ImportError:
            logger.warning("autogen_not_installed", hint="pip install pyautogen")
            self._agent = None

        logger.info("autogen_shield_active", agent=name, tenant_id=tenant_id)

    def generate_reply(
        self,
        messages: Optional[list[dict]] = None,
        sender: Optional[Any] = None,
        **kwargs: Any,
    ) -> Optional[str]:
        """
        Intercept AutoGen's generate_reply to scan input and output.
        """
        if messages:
            # Scan incoming messages
            for msg in messages:
                content = msg.get("content", "")
                if content:
                    self._shield_check(prompt=content, source="autogen_input")

        if self._agent is None:
            return None

        # Generate reply from wrapped agent
        reply = self._agent.generate_reply(messages=messages, sender=sender, **kwargs)

        # Scan outgoing reply
        if reply:
            self._shield_check(
                prompt=messages[-1].get("content", "") if messages else "",
                completion=reply,
                source="autogen_output",
            )

        return reply

    def initiate_chat(self, recipient: Any, message: str, **kwargs: Any) -> Any:
        """Intercept chat initiation."""
        self._shield_check(prompt=message, source="autogen_initiate")
        if self._agent:
            return self._agent.initiate_chat(recipient, message=message, **kwargs)

    def _shield_check(
        self,
        prompt: str,
        completion: Optional[str] = None,
        source: str = "autogen",
    ) -> None:
        try:
            from ai_shield.client import Shield
            shield = Shield(api_key=self._api_key, base_url=self._base_url)
            verdict = shield.inspect_sync(prompt=prompt, completion=completion)
            if verdict.blocked and self._raise:
                raise PermissionError(
                    f"[AI Shield] AutoGen {source} blocked. "
                    f"Severity: {verdict.severity}. "
                    f"Agent: {self.name}"
                )
            logger.info(
                "autogen_inspect",
                source=source,
                action=verdict.action,
                agent=self.name,
            )
        except PermissionError:
            raise
        except Exception as e:
            logger.warning("autogen_inspect_failed", error=str(e))

    def __getattr__(self, name: str) -> Any:
        """Pass through any AutoGen-specific attributes."""
        if self._agent and hasattr(self._agent, name):
            return getattr(self._agent, name)
        raise AttributeError(f"ShieldedConversableAgent has no attribute '{name}'")


class ShieldedCrewTask:
    """
    CrewAI Task wrapper with AI Shield monitoring.

    Intercepts task execution to scan inputs and outputs.

    Usage:
        task = ShieldedCrewTask(
            description="Analyse the quarterly report",
            shield_api_key="your-key",
            expected_output="A summary with key findings",
            agent=analyst_agent,
        )
    """

    def __init__(
        self,
        description: str,
        shield_api_key: str = "",
        shield_base_url: str = "https://api.aishield.tinlance.com",
        tenant_id: str = "",
        raise_on_block: bool = True,
        **crewai_kwargs: Any,
    ) -> None:
        self._api_key   = shield_api_key
        self._base_url  = shield_base_url
        self._tenant_id = tenant_id
        self._raise     = raise_on_block

        # Scan task description for poisoning at creation time
        self._shield_check(prompt=description, source="crewai_task_creation")

        try:
            from crewai import Task
            self._task = Task(description=description, **crewai_kwargs)
        except ImportError:
            logger.warning("crewai_not_installed", hint="pip install crewai")
            self._task = None

    def _shield_check(self, prompt: str, completion: Optional[str] = None, source: str = "") -> None:
        try:
            from ai_shield.client import Shield
            shield = Shield(api_key=self._api_key, base_url=self._base_url)
            verdict = shield.inspect_sync(prompt=prompt, completion=completion)
            if verdict.blocked and self._raise:
                raise PermissionError(
                    f"[AI Shield] CrewAI {source} blocked. Severity: {verdict.severity}."
                )
        except PermissionError:
            raise
        except Exception as e:
            logger.warning("crewai_inspect_failed", error=str(e))

    def __getattr__(self, name: str) -> Any:
        if self._task and hasattr(self._task, name):
            return getattr(self._task, name)
        raise AttributeError(f"ShieldedCrewTask has no attribute '{name}'")
