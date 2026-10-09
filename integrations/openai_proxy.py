"""Legacy import path; delegates to the canonical Aithyrex SDK wrapper.

This module intentionally does not instantiate ShieldEngine locally. Local
engine construction bypassed API authentication, server-side entitlements and
tenant resolution. New code should import from aithyrex.integrations.openai.
"""
from ai_shield.integrations.openai import ShieldedOpenAI, wrap

__all__ = ["ShieldedOpenAI", "wrap"]
