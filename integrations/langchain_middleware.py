"""Legacy import path for the supported Aithyrex LangChain callback.

Callbacks are defense-in-depth and are not the authoritative tool-execution gate.
"""
from ai_shield.integrations.langchain import AIShieldCallback, AithyrexCallback

__all__ = ["AIShieldCallback", "AithyrexCallback"]
