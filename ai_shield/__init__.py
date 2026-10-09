"""
AI Shield — Runtime Security for LLM and Agentic AI Systems
============================================================
Production-validated C2 detection applied to AI model traffic.

Quick start:
    pip install ai-shield

    from ai_shield import wrap
    import openai

    client = wrap(openai.OpenAI(api_key="..."), api_key="your-shield-key")
    response = client.chat.completions.create(...)

Or use the direct API:
    from ai_shield import Shield

    shield = Shield(api_key="your-shield-key")
    verdict = shield.inspect(prompt=user_input, completion=model_output)
    if verdict.blocked:
        raise SecurityError("Blocked by AI Shield")

GitHub:  https://github.com/Tinlance/ai-shield
Docs:    https://tinlance.com/ai-shield
PyPI:    https://pypi.org/project/ai-shield
"""

__version__ = "0.1.0"
__author__  = "Tinlance Limited"
__license__ = "Apache-2.0"

from ai_shield.client import Shield
from ai_shield.integrations.openai  import wrap as wrap_openai
from ai_shield.integrations.anthropic import wrap as wrap_anthropic

def wrap(client, api_key: str = "", tenant_id: str = "", plan: str = "free"):
    """
    Auto-detect client type and wrap with AI Shield.

    Supports: openai.OpenAI, anthropic.Anthropic

    Usage:
        import openai
        from ai_shield import wrap
        client = wrap(openai.OpenAI(...), api_key="your-shield-key")
    """
    client_type = type(client).__name__

    if "OpenAI" in client_type:
        return wrap_openai(client, api_key=api_key, tenant_id=tenant_id, plan=plan)
    elif "Anthropic" in client_type:
        return wrap_anthropic(client, api_key=api_key, tenant_id=tenant_id, plan=plan)
    else:
        raise TypeError(
            f"Unsupported client type: {client_type}. "
            "Supported: openai.OpenAI, anthropic.Anthropic. "
            "For LangChain use: from ai_shield.integrations.langchain import AIShieldCallback"
        )

__all__ = ["Shield", "wrap", "wrap_openai", "wrap_anthropic", "__version__"]
