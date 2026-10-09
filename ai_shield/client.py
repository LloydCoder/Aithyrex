"""Aithyrex HTTP client; ai_shield is retained as a legacy import namespace."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


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
    action: str
    severity: str
    blocked: bool
    detections: list[Detection] = field(default_factory=list)
    tenant_id: str = ""
    degraded: bool = False
    error_code: str | None = None

    def detected_by(self, detector_name: str) -> bool:
        return any(d.detector == detector_name and d.detected for d in self.detections)


def _blocked(error_code: str) -> ShieldVerdict:
    """Conservative verdict for any missing configuration or failed inspection."""
    return ShieldVerdict(
        action="block",
        severity="high",
        blocked=True,
        degraded=True,
        error_code=error_code,
    )


class Shield:
    """Aithyrex API client; the credential must be a verified Clerk session JWT.

    No hosted endpoint is assumed. Configure AITHYREX_API_URL or pass base_url.
    The api_key argument is retained for compatibility but is treated as a bearer
    session token; Aithyrex does not currently implement generic static API keys.
    """

    def __init__(
        self,
        api_key: str = "",
        base_url: str | None = None,
        timeout: float = 10.0,
        *,
        token: str | None = None,
    ) -> None:
        self.api_key = api_key
        self.token = token or api_key or os.getenv("AITHYREX_API_TOKEN", "")
        self.base_url = (base_url or os.getenv("AITHYREX_API_URL", "")).rstrip("/")
        self.timeout = timeout
        self._headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}",
        }

    async def inspect(
        self,
        prompt: str,
        completion: Optional[str] = None,
        model: Optional[str] = None,
    ) -> ShieldVerdict:
        """Inspect content. Configuration, transport and schema errors fail closed."""
        if not self.base_url:
            return _blocked("api_url_not_configured")
        if not self.token:
            return _blocked("session_token_not_configured")

        try:
            import httpx
        except ImportError:
            return _blocked("httpx_not_installed")

        parsed = urlparse(self.base_url)
        local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not local_http:
            return _blocked("insecure_api_url")

        payload: dict = {"prompt": prompt}
        if completion is not None:
            payload["completion"] = completion
        if model is not None:
            payload["model"] = model

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/detect/llm",
                    headers=self._headers,
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
        except httpx.TimeoutException:
            return _blocked("inspection_timeout")
        except httpx.ConnectError:
            return _blocked("inspection_unreachable")
        except httpx.HTTPStatusError as exc:
            return _blocked(f"inspection_http_{exc.response.status_code}")
        except (httpx.HTTPError, ValueError):
            return _blocked("inspection_transport_or_json_error")
        except Exception:
            return _blocked("inspection_unexpected_error")

        if not isinstance(data, dict):
            return _blocked("invalid_response_schema")
        action = data.get("action")
        severity = data.get("severity")
        blocked = data.get("blocked")
        raw_detections = data.get("detections")
        if (
            action not in {"pass", "log", "alert", "block"}
            or severity not in {"clean", "info", "low", "medium", "high", "critical"}
            or not isinstance(blocked, bool)
            or not isinstance(raw_detections, list)
        ):
            return _blocked("invalid_response_schema")
        if action == "block":
            blocked = True

        detections: list[Detection] = []
        for item in raw_detections:
            if not isinstance(item, dict):
                return _blocked("invalid_detection_schema")
            if not isinstance(item.get("detector"), str) or not isinstance(item.get("detected"), bool):
                return _blocked("invalid_detection_schema")
            try:
                confidence = float(item.get("confidence", 0.0))
            except (TypeError, ValueError):
                return _blocked("invalid_detection_schema")
            if not 0.0 <= confidence <= 1.0:
                return _blocked("invalid_detection_schema")
            detections.append(
                Detection(
                    detector=item["detector"],
                    detected=item["detected"],
                    severity=str(item.get("severity", "info")),
                    confidence=confidence,
                    mitre_atlas=item.get("mitre_atlas", []),
                    details=item.get("details", {}),
                )
            )

        return ShieldVerdict(
            action=action,
            severity=severity,
            blocked=blocked,
            tenant_id=str(data.get("tenant_id", "")),
            detections=detections,
        )

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
                import concurrent.futures

                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, self.inspect(prompt, completion, model))
                    return future.result()
            return loop.run_until_complete(self.inspect(prompt, completion, model))
        except RuntimeError:
            return asyncio.run(self.inspect(prompt, completion, model))

    async def health(self) -> dict:
        """Check service health without claiming that a missing URL is reachable."""
        if not self.base_url:
            return {"status": "unconfigured"}
        try:
            import httpx

            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.base_url}/health")
                response.raise_for_status()
                result = response.json()
                return result if isinstance(result, dict) else {"status": "invalid_response"}
        except Exception as exc:
            return {"status": "unreachable", "error_type": type(exc).__name__}


AithyrexClient = Shield
