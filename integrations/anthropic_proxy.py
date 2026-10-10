"""Legacy import path; delegates to the canonical Aithyrex SDK wrapper.

This module intentionally does not instantiate ShieldEngine locally. Local
engine construction bypassed API authentication, server-side entitlements and
tenant resolution. New code should import from aithyrex.integrations.anthropic.
"""
from ai_shield.integrations.anthropic import ShieldedAnthropic, wrap

__all__ = ["ShieldedAnthropic", "wrap"]
