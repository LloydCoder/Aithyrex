"""
AI Shield — Python Client
==========================
Lightweight HTTP client for the AI Shield API.
No heavy dependencies — just httpx.

Usage:
    shield = Shield(api_key="your-key", base_url="https://api.aishield.tinlance.com")
    verdict = await shield.inspect(prompt="...", completion="...")
    if verdict.blocked:
        raise SecurityError(f"Blocked: {verdict.severity}")
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Detection:
    detector: str
    detected: bool
    severity: str
    confidence: float
    mitre_atlas: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)


@dataclass
class ShieldVerdict:
    action: str        # "pass" | "log" | "alert" | "block"
    severity: str      # "clean" | "low" | "medium" | "high" | "critical"
    blocked: bool
    detections: list[Detection] = field(default_factory=list)
    tenant_id: str = ""

    def detected_by(self, detector_name: str) -> bool:
        return any(d.detector == detector_name and d.detected for d in self.detections)


class Shield:
    """
    AI Shield API client.

    Connects to the AI Shield FastAPI backend.
    Can be self-hosted or use the hosted service at api.aishield.tinlance.com.

    Usage:
        # Async
        shield = Shield(api_key="your-key")
        verdict = await shield.inspect(prompt=user_input)

        # Sync
        verdict = shield.inspect_sync(prompt=user_input)
    """

    def __init__(
        self,
        api_key: str = "",
        base_url: str = "https://api.aishield.tinlance.com",
        timeout: float = 10.0,
    ) -> None:
        self.api_key  = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout
        self._headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }

    async def inspect(
        self,
        prompt: str,
        completion: Optional[str] = None,
        model: Optional[str] = None,
    ) -> ShieldVerdict:
        """
        Inspect a prompt/completion pair.

        Args:
            prompt:     The input sent to the LLM.
            completion: The LLM output (optional for pre-flight checks).
            model:      Model identifier for logging.

        Returns:
            ShieldVerdict with action, severity, blocked flag, and detections.
        """
        try:
            import httpx
        except ImportError:
            raise ImportError("httpx is required: pip install httpx")

        payload: dict = {"prompt": prompt}
        if completion is not None:
            payload["completion"] = completion
        if model is not None:
            payload["model"] = model

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.post(
                    f"{self.base_url}/detect/llm",
                    headers=self._headers,
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()

                return ShieldVerdict(
                    action=data.get("action", "pass"),
                    severity=data.get("severity", "clean"),
                    blocked=data.get("blocked", False),
                    tenant_id=data.get("tenant_id", ""),
                    detections=[
                        Detection(
                            detector=d["detector"],
                            detected=d["detected"],
                            severity=d["severity"],
                            confidence=d["confidence"],
                            mitre_atlas=d.get("mitre_atlas", []),
                            details=d.get("details", {}),
                        )
                        for d in data.get("detections", [])
                    ],
                )

            except httpx.TimeoutException:
                # Graceful degradation — never block on SDK timeout
                return ShieldVerdict(action="pass", severity="clean", blocked=False)
            except httpx.ConnectError:
                return ShieldVerdict(action="pass", severity="clean", blocked=False)

    def inspect_sync(
        self,
        prompt: str,
        completion: Optional[str] = None,
        model: Optional[str] = None,
    ) -> ShieldVerdict:
        """Synchronous wrapper around inspect() for non-async contexts."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Inside an existing event loop (FastAPI, Jupyter, etc.)
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(
                        asyncio.run,
                        self.inspect(prompt, completion, model),
                    )
                    return future.result()
            else:
                return loop.run_until_complete(
                    self.inspect(prompt, completion, model)
                )
        except RuntimeError:
            return asyncio.run(self.inspect(prompt, completion, model))

    async def health(self) -> dict:
        """Check AI Shield API health."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(f"{self.base_url}/health", headers=self._headers)
                return r.json()
        except Exception as e:
            return {"status": "unreachable", "error": str(e)}
