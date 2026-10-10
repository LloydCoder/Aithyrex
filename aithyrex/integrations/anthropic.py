"""
Aithyrex — Anthropic Integration (PyPI package)
==================================================
Usage:
    from ai_shield.integrations.anthropic import wrap
    import anthropic

    client = wrap(anthropic.Anthropic(api_key="..."), api_key="your-shield-key")
    response = client.messages.create(model="claude-sonnet-4-6", messages=[...])
"""

from __future__ import annotations

import inspect
import json

from aithyrex.client import Shield


class ShieldedAnthropic:
    def __init__(self, client, shield: Shield):
        if inspect.iscoroutinefunction(client.messages.create):
            raise NotImplementedError("AsyncAnthropic is not supported by this wrapper; use a mediation gateway")
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
        if kwargs.get("stream"):
            raise NotImplementedError("Streaming is unsupported; use a mediation gateway that buffers output")
        messages = kwargs.get("messages", [])
        system = kwargs.get("system", "")
        model = kwargs.get("model", "unknown")
        prompt_parts = []
        if isinstance(system, str):
            prompt_parts.append("system: " + system)
        elif system:
            raise NotImplementedError("Non-text system content is not supported by this wrapper")
        for message in messages:
            if not isinstance(message, dict):
                raise ValueError("each message must be an object")
            content = message.get("content")
            if content is None:
                continue
            if isinstance(content, str):
                prompt_parts.append(f"{message.get('role', 'unknown')}: {content}")
            elif isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict) or block.get("type") != "text" or not isinstance(block.get("text"), str):
                        raise NotImplementedError("Multimodal/tool-result input is not supported by this wrapper")
                    prompt_parts.append(f"{message.get('role', 'unknown')}: {block['text']}")
            else:
                raise NotImplementedError("Unsupported message content type")
        prompt = "\n".join(prompt_parts)

        pre = self._shield.inspect_sync(prompt=prompt, model=model)
        if pre.blocked:
            raise PermissionError(
                f"[Aithyrex] Prompt blocked. Severity: {pre.severity}."
            )

        response = self._messages.create(**kwargs)

        completion_parts = []
        for block in response.content:
            if getattr(block, "type", "") == "text":
                completion_parts.append(block.text)
            elif getattr(block, "type", "") == "tool_use":
                completion_parts.append(
                    json.dumps({"tool": block.name, "input": block.input}, sort_keys=True)
                )
        completion = "\n".join(completion_parts)

        if completion:
            post = self._shield.inspect_sync(
                prompt=prompt, completion=completion, model=model
            )
            if post.blocked:
                raise PermissionError(
                    f"[Aithyrex] Completion blocked. Severity: {post.severity}."
                )

        return response


def wrap(
    client,
    api_key: str = "",
    base_url: str | None = None,
    tenant_id: str = "",
    plan: str = "free",
    token: str | None = None,
) -> ShieldedAnthropic:
    """Wrap a synchronous Anthropic client with Aithyrex inspection."""
    shield = Shield(api_key=api_key, base_url=base_url, token=token)
    return ShieldedAnthropic(client, shield)
