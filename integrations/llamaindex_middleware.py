"""Legacy import path for the supported Aithyrex LlamaIndex observer.

The observer is defense-in-depth, not an authoritative execution boundary.
"""
from ai_shield.integrations.llamaindex import AIShieldObserver

__all__ = ["AIShieldObserver"]
