"""
AI Shield — OpenAI Proxy Interceptor
======================================
Wraps the OpenAI client. Intercepts every chat completion
through ShieldEngine — blocks malicious prompts before they
reach OpenAI, scans completions before they reach your app.

Usage:
    from ai_shield.integrations.openai_proxy import wrap
    import openai

    client = wrap(openai.OpenAI(api_key="..."), tenant_id="org_123", plan="pro")
    response = client.chat.completions.create(...)
    # Transparent — your code changes nothing else
"""

from __future__ import annotations
import asyncio
import structlog

logger = structlog.get_logger(__name__)


class ShieldedOpenAI:
    def __init__(self, client, tenant_id: str = "", plan: str = "free"):
        self._client = client
        self._tenant_id = tenant_id
        self._plan = plan
        self.chat = ShieldedChat(client.chat, tenant_id, plan)
        logger.info("openai_proxy_active", tenant_id=tenant_id, plan=plan)


class ShieldedChat:
    def __init__(self, chat, tenant_id: str, plan: str):
        self._chat = chat
        self.completions = ShieldedCompletions(chat.completions, tenant_id, plan)


class ShieldedCompletions:
    def __init__(self, completions, tenant_id: str, plan: str):
        self._completions = completions
        self._tenant_id = tenant_id
        self._plan = plan

    def create(self, **kwargs):
        """
        Intercept OpenAI chat completion.
        1. Pre-flight scan of prompt — block before sending to OpenAI
        2. Forward to OpenAI if clean
        3. Post-completion scan — block if completion contains threats
        """
        from backend.core.shield_engine import ShieldEngine, Action
        engine = ShieldEngine()

        messages = kwargs.get("messages", [])
        model = kwargs.get("model", "unknown")
        prompt = " ".join(
            m.get("content", "") for m in messages
            if isinstance(m.get("content"), str) and m.get("role") == "user"
        )

        # Pre-flight scan — sync wrapper around async inspect
        pre_verdict = asyncio.get_event_loop().run_until_complete(
            engine.inspect(
                prompt=prompt,
                tenant_id=self._tenant_id,
                model=model,
                plan=self._plan,
            )
        )

        if pre_verdict.blocked:
            logger.warning(
                "openai_proxy_prompt_blocked",
                tenant_id=self._tenant_id,
                model=model,
                severity=pre_verdict.severity,
            )
            raise PermissionError(
                f"AI Shield blocked this prompt. "
                f"Severity: {pre_verdict.severity}. "
                f"Detectors: {[r.detector for r in pre_verdict.results if r.detected]}"
            )

        # Forward to OpenAI
        response = self._completions.create(**kwargs)

        # Post-completion scan
        completion = ""
        if response.choices:
            completion = response.choices[0].message.content or ""

        if completion:
            post_verdict = asyncio.get_event_loop().run_until_complete(
                engine.inspect(
                    prompt=prompt,
                    completion=completion,
                    tenant_id=self._tenant_id,
                    model=model,
                    plan=self._plan,
                )
            )
            if post_verdict.blocked:
                logger.critical(
                    "openai_proxy_completion_blocked",
                    tenant_id=self._tenant_id,
                    model=model,
                    severity=post_verdict.severity,
                )
                raise PermissionError(
                    f"AI Shield blocked this completion. "
                    f"Severity: {post_verdict.severity}."
                )

        return response


def wrap(client, tenant_id: str = "", plan: str = "free") -> ShieldedOpenAI:
    """Wrap an OpenAI client with AI Shield monitoring."""
    return ShieldedOpenAI(client, tenant_id=tenant_id, plan=plan)
