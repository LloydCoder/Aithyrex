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

import inspect

from ai_shield.client import Shield


def _extract_text_messages(messages) -> str:
    if not isinstance(messages, list):
        raise ValueError("messages must be a list")
    parts = []
    for message in messages:
        if not isinstance(message, dict):
            raise ValueError("each message must be an object")
        content = message.get("content")
        if content is None:
            continue
        if not isinstance(content, str):
            raise NotImplementedError("Multimodal content is not supported by this wrapper")
        parts.append(f"{message.get('role', 'unknown')}: {content}")
    return "\n".join(parts)


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
        self._async = inspect.iscoroutinefunction(completions.create)

    def create(self, **kwargs):
        if self._async:
            return self._create_async(**kwargs)
        return self._create_sync(**kwargs)

    def _create_sync(self, **kwargs):
        if kwargs.get("stream"):
            raise NotImplementedError("Streaming is unsupported; use a mediation gateway that buffers output")
        messages = kwargs.get("messages", [])
        model = kwargs.get("model", "unknown")
        prompt = _extract_text_messages(messages)

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
            message = response.choices[0].message
            completion = message.content or ""
            tool_calls = getattr(message, "tool_calls", None) or []
            if tool_calls:
                completion += "\n" + "\n".join(
                    f"tool={call.function.name} arguments={call.function.arguments}"
                    for call in tool_calls
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

    async def _create_async(self, **kwargs):
        """Async path for AsyncOpenAI; streaming remains explicitly unsupported."""
        if kwargs.get("stream"):
            raise NotImplementedError("Streaming is unsupported; use a mediation gateway that buffers output")
        messages = kwargs.get("messages", [])
        model = kwargs.get("model", "unknown")
        prompt = _extract_text_messages(messages)

        pre = await self._shield.inspect(prompt=prompt, model=model)
        if pre.blocked:
            raise PermissionError(f"[AI Shield] Prompt blocked. Severity: {pre.severity}.")

        response = await self._completions.create(**kwargs)

        completion = ""
        if response.choices:
            message = response.choices[0].message
            completion = message.content or ""
            tool_calls = getattr(message, "tool_calls", None) or []
            if tool_calls:
                completion += "\n" + "\n".join(
                    f"tool={call.function.name} arguments={call.function.arguments}"
                    for call in tool_calls
                )

        if completion:
            post = await self._shield.inspect(prompt=prompt, completion=completion, model=model)
            if post.blocked:
                raise PermissionError(f"[AI Shield] Completion blocked.")

        return response

    async def acreate(self, **kwargs):
        """Compatibility alias for explicit async callers."""
        return await self._create_async(**kwargs)


def wrap(
    client,
    api_key: str = "",
    base_url: str | None = None,
    tenant_id: str = "",
    plan: str = "free",
    token: str | None = None,
) -> ShieldedOpenAI:
    """Wrap an OpenAI client with Aithyrex pre/post-flight inspection."""
    shield = Shield(api_key=api_key, base_url=base_url, token=token)
    return ShieldedOpenAI(client, shield)
