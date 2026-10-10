"""Aithyrex HTTP client; ai_shield is retained as a legacy import namespace."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse
from uuid import UUID, uuid4


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
    trace_id: str | None = None

    def detected_by(self, detector_name: str) -> bool:
        return any(d.detector == detector_name and d.detected for d in self.detections)


def _blocked(error_code: str, trace_id: str | None = None) -> ShieldVerdict:
    """Conservative verdict for any missing configuration or failed inspection."""
    return ShieldVerdict(
        action="block",
        severity="high",
        blocked=True,
        degraded=True,
        error_code=error_code,
        trace_id=trace_id,
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
        request_id = str(uuid4())
        if not self.base_url:
            return _blocked("api_url_not_configured", request_id)
        if not self.token:
            return _blocked("session_token_not_configured", request_id)

        try:
            import httpx
        except ImportError:
            return _blocked("httpx_not_installed", request_id)

        parsed = urlparse(self.base_url)
        local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme != "https" and not local_http:
            return _blocked("insecure_api_url")

        request_id = str(uuid4())
        request_headers = {**self._headers, "X-Request-ID": request_id}

        payload: dict = {"prompt": prompt}
        if completion is not None:
            payload["completion"] = completion
        if model is not None:
            payload["model"] = model

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/v1/detect/llm",
                    headers=request_headers,
                    json=payload,
                )
                response.raise_for_status()
                data = response.json()
        except httpx.TimeoutException:
            return _blocked("inspection_timeout", request_id)
        except httpx.ConnectError:
            return _blocked("inspection_unreachable", request_id)
        except httpx.HTTPStatusError as exc:
            return _blocked(f"inspection_http_{exc.response.status_code}", request_id)
        except (httpx.HTTPError, ValueError):
            return _blocked("inspection_transport_or_json_error", request_id)
        except Exception:
            return _blocked("inspection_unexpected_error", request_id)

        if not isinstance(data, dict):
            return _blocked("invalid_response_schema", request_id)
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
        response_trace_id = data.get("trace_id")
        header_trace_id = response.headers.get("X-Request-ID")
        for candidate in (response_trace_id, header_trace_id):
            if candidate is not None:
                try:
                    UUID(str(candidate))
                except (ValueError, TypeError, AttributeError):
                    return _blocked("invalid_trace_id", request_id)
        if response_trace_id and header_trace_id and str(response_trace_id) != str(header_trace_id):
            return _blocked("trace_id_mismatch", request_id)
        trace_id = str(response_trace_id or header_trace_id or request_id)
        if trace_id != request_id:
            return _blocked("trace_id_mismatch", request_id)

        if action == "block":
            blocked = True

        detections: list[Detection] = []
        for item in raw_detections:
            if not isinstance(item, dict):
                return _blocked("invalid_detection_schema", request_id)
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
            trace_id=trace_id,
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
