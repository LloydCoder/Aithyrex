"""Legacy import namespace for Aithyrex.

Use the canonical distribution and import namespace, aithyrex, for new code.
The ai_shield namespace remains for compatibility with existing integrations.
"""

__version__ = "0.1.0"
__author__ = "Tinlance Limited"
__license__ = "Apache-2.0"

from ai_shield.client import AithyrexClient, Detection, Shield, ShieldVerdict
from ai_shield.integrations.anthropic import wrap as wrap_anthropic
from ai_shield.integrations.openai import wrap as wrap_openai


def wrap(
    client,
    api_key: str = "",
    tenant_id: str = "",
    plan: str = "free",
    *,
    token: str | None = None,
    base_url: str | None = None,
):
    """Wrap a supported synchronous provider client with Aithyrex inspection.

    The credential is a Clerk session JWT (token). Generic static API keys are
    not currently supported. Set AITHYREX_API_URL or pass base_url explicitly.
    """
    client_type = type(client).__name__
    options = {
        "api_key": api_key,
        "token": token,
        "base_url": base_url,
        "tenant_id": tenant_id,
        "plan": plan,
    }
    if "OpenAI" in client_type:
        return wrap_openai(client, **options)
    if "Anthropic" in client_type:
        return wrap_anthropic(client, **options)
    raise TypeError(
        f"Unsupported client type: {client_type}. "
        "Supported wrappers are synchronous OpenAI and Anthropic clients; "
        "streaming, multimodal inputs and AsyncAnthropic are not supported."
    )


__all__ = [
    "AithyrexClient",
    "Detection",
    "Shield",
    "ShieldVerdict",
    "wrap",
    "wrap_openai",
    "wrap_anthropic",
    "__version__",
]
