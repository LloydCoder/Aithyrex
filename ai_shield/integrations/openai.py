"""
AI Shield — OpenAI Integration (PyPI package)
===============================================
Lightweight wrapper for the OpenAI SDK.
Calls the AI Shield API for each request — no local models.

Usage:
    from ai_shield.integrations.openai import wrap
    import openai

    client = wrap(openai.OpenAI(api_key="..."), api_key="your-shield-key")
    response = client.chat.completions.create(model="gpt-4o", messages=[...])
"""

from __future__ import annotations
from ai_shield.client import Shield


class ShieldedOpenAI:
    def __init__(self, client, shield: Shield):
        self._client = client
        self._shield = shield
        self.chat = _ShieldedChat(client.chat, shield)

    def __getattr__(self, name):
        # Pass through any other OpenAI client attributes
        return getattr(self._client, name)


class _ShieldedChat:
    def __init__(self, chat, shield: Shield):
        self._chat = chat
        self.completions = _ShieldedCompletions(chat.completions, shield)


class _ShieldedCompletions:
    def __init__(self, completions, shield: Shield):
        self._completions = completions
        self._shield = shield

    def create(self, **kwargs):
        messages = kwargs.get("messages", [])
        model    = kwargs.get("model", "unknown")
        prompt   = " ".join(
            m.get("content", "") for m in messages
            if isinstance(m.get("content"), str) and m.get("role") == "user"
        )

        # Pre-flight check
        pre = self._shield.inspect_sync(prompt=prompt, model=model)
        if pre.blocked:
            raise PermissionError(
                f"[AI Shield] Prompt blocked. "
                f"Severity: {pre.severity}. "
                f"Detectors: {[d.detector for d in pre.detections if d.detected]}"
            )

        response = self._completions.create(**kwargs)

        # Post-completion check
        completion = ""
        if response.choices:
            completion = response.choices[0].message.content or ""

        if completion:
            post = self._shield.inspect_sync(
                prompt=prompt, completion=completion, model=model
            )
            if post.blocked:
                raise PermissionError(
                    f"[AI Shield] Completion blocked. Severity: {post.severity}."
                )

        return response

    async def acreate(self, **kwargs):
        """Async version for async OpenAI usage."""
        messages = kwargs.get("messages", [])
        model    = kwargs.get("model", "unknown")
        prompt   = " ".join(
            m.get("content", "") for m in messages
            if isinstance(m.get("content"), str) and m.get("role") == "user"
        )

        pre = await self._shield.inspect(prompt=prompt, model=model)
        if pre.blocked:
            raise PermissionError(f"[AI Shield] Prompt blocked. Severity: {pre.severity}.")

        response = await self._completions.acreate(**kwargs)

        completion = ""
        if response.choices:
            completion = response.choices[0].message.content or ""

        if completion:
            post = await self._shield.inspect(prompt=prompt, completion=completion, model=model)
            if post.blocked:
                raise PermissionError(f"[AI Shield] Completion blocked.")

        return response


def wrap(
    client,
    api_key: str = "",
    base_url: str = "https://api.aishield.tinlance.com",
    tenant_id: str = "",
    plan: str = "free",
) -> ShieldedOpenAI:
    """Wrap an OpenAI client with AI Shield monitoring."""
    shield = Shield(api_key=api_key, base_url=base_url)
    return ShieldedOpenAI(client, shield)
