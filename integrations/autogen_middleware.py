"""Explicitly unsupported legacy AutoGen/CrewAI middleware.

The previous wrapper could silently continue after inspection errors and did not
prove complete pre-side-effect coverage. Refuse construction rather than imply
that agents are protected. Use the Aithyrex API directly and keep authoritative
tool authorization in the Tinlance Agent Platform.
"""

class ShieldedConversableAgent:
    """Deprecated placeholder; no production-safe AutoGen adapter is shipped."""

    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "Aithyrex AutoGen mediation is not supported. "
            "Do not use a callback as an execution security boundary."
        )


class ShieldedCrewTask:
    """Deprecated placeholder; no production-safe CrewAI adapter is shipped."""

    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "Aithyrex CrewAI mediation is not supported. "
            "Do not use a task wrapper as an execution security boundary."
        )


__all__ = ["ShieldedConversableAgent", "ShieldedCrewTask"]
