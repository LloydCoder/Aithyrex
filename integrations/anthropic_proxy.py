"""
AI Shield — Anthropic Proxy Interceptor
=========================================
Wraps the Anthropic client. Zero code changes required
beyond the initial wrap() call.

Usage:
    from ai_shield.integrations.anthropic_proxy import wrap
    import anthropic

    client = wrap(anthropic.Anthropic(api_key="..."), tenant_id="org_123", plan="pro")
    response = client.messages.create(...)
"""

from __future__ import annotations
import asyncio
import structlog

logger = structlog.get_logger(__name__)


class ShieldedAnthropic:
    def __init__(self, client, tenant_id: str = "", plan: str = "free"):
        self._client = client
        self._tenant_id = tenant_id
        self._plan = plan
        self.messages = ShieldedMessages(client.messages, tenant_id, plan)
        logger.info("anthropic_proxy_active", tenant_id=tenant_id, plan=plan)


class ShieldedMessages:
    def __init__(self, messages, tenant_id: str, plan: str):
        self._messages = messages
        self._tenant_id = tenant_id
        self._plan = plan

    def create(self, **kwargs):
        """Intercept Anthropic messages.create()."""
        from backend.core.shield_engine import ShieldEngine, Action
        engine = ShieldEngine()

        messages = kwargs.get("messages", [])
        system = kwargs.get("system", "")
        model = kwargs.get("model", "claude-sonnet-4-6")

        prompt = system + " " + " ".join(
            m.get("content", "") for m in messages
            if isinstance(m.get("content"), str) and m.get("role") == "user"
        )

        # Pre-flight scan
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
                "anthropic_proxy_prompt_blocked",
                tenant_id=self._tenant_id,
                severity=pre_verdict.severity,
            )
            raise PermissionError(
                f"AI Shield blocked this prompt. Severity: {pre_verdict.severity}."
            )

        # Forward to Anthropic
        response = self._messages.create(**kwargs)

        # Post-completion scan
        completion = " ".join(
            block.text for block in response.content
            if hasattr(block, "text")
        )

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
                    "anthropic_proxy_completion_blocked",
                    severity=post_verdict.severity,
                )
                raise PermissionError(
                    f"AI Shield blocked this completion. Severity: {post_verdict.severity}."
                )

        return response


def wrap(client, tenant_id: str = "", plan: str = "free") -> ShieldedAnthropic:
    """Wrap an Anthropic client with AI Shield monitoring."""
    return ShieldedAnthropic(client, tenant_id=tenant_id, plan=plan)
