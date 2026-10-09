"""
AI Shield — Anthropic Integration (PyPI package)
==================================================
Usage:
    from ai_shield.integrations.anthropic import wrap
    import anthropic

    client = wrap(anthropic.Anthropic(api_key="..."), api_key="your-shield-key")
    response = client.messages.create(model="claude-sonnet-4-6", messages=[...])
"""

from __future__ import annotations
from ai_shield.client import Shield


class ShieldedAnthropic:
    def __init__(self, client, shield: Shield):
        self._client = client
        self._shield = shield
        self.messages = _ShieldedMessages(client.messages, shield)

    def __getattr__(self, name):
        return getattr(self._client, name)


class _ShieldedMessages:
    def __init__(self, messages, shield: Shield):
        self._messages = messages
        self._shield = shield

    def create(self, **kwargs):
        messages = kwargs.get("messages", [])
        system   = kwargs.get("system", "")
        model    = kwargs.get("model", "claude-sonnet-4-6")
        prompt   = system + " " + " ".join(
            m.get("content", "") for m in messages
            if isinstance(m.get("content"), str) and m.get("role") == "user"
        )

        pre = self._shield.inspect_sync(prompt=prompt, model=model)
        if pre.blocked:
            raise PermissionError(
                f"[AI Shield] Prompt blocked. Severity: {pre.severity}."
            )

        response = self._messages.create(**kwargs)

        completion = " ".join(
            b.text for b in response.content if hasattr(b, "text")
        )

        if completion:
            post = self._shield.inspect_sync(
                prompt=prompt, completion=completion, model=model
            )
            if post.blocked:
                raise PermissionError(
                    f"[AI Shield] Completion blocked. Severity: {post.severity}."
                )

        return response


def wrap(
    client,
    api_key: str = "",
    base_url: str = "https://api.aishield.tinlance.com",
    tenant_id: str = "",
    plan: str = "free",
) -> ShieldedAnthropic:
    """Wrap an Anthropic client with AI Shield monitoring."""
    shield = Shield(api_key=api_key, base_url=base_url)
    return ShieldedAnthropic(client, shield)
