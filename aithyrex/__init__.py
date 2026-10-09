"""Canonical Aithyrex Python import namespace."""
from ai_shield import __version__, wrap, wrap_anthropic, wrap_openai
from ai_shield.client import AithyrexClient, Detection, Shield, ShieldVerdict

__all__ = [
    "AithyrexClient", "Detection", "Shield", "ShieldVerdict",
    "wrap", "wrap_openai", "wrap_anthropic", "__version__",
]
