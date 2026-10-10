"""
Aithyrex — ThreatFade HTTP Client
====================================
Calls the ThreatFade C2 detection engine via HTTP.

ThreatFade repo: github.com/LloydCoder/tinlance-threatfade
API pattern: same as FusionOps fusionops_api.py implementation.

No code duplication — ThreatFade runs as a separate service.
Improvements to ThreatFade automatically benefit Aithyrex.
"""

from __future__ import annotations

import math

import httpx
import structlog

from backend.core.config import settings

logger = structlog.get_logger(__name__)


class ThreatFadeClient:
    """
    HTTP client for ThreatFade v0.2.0-beta API.

    Endpoints used:
        POST /detect/json   — analyse arbitrary text for C2 indicators
        GET  /health        — liveness check
    """

    def __init__(self) -> None:
        self._base_url = settings.THREATFADE_API_URL
        self._headers = {
            "X-API-Key": settings.THREATFADE_API_KEY,
            "Content-Type": "application/json",
        }

    # An outage is not a clean verdict; callers must treat telemetry as degraded.
    _DEGRADED_RESPONSE: dict = {
        "detected": False,
        "confidence": "unknown",
        "score": 0.0,
        "entropy": 0.0,
        "z_outlier": 0.0,
        "rules_matched": 0,
        "mitre_ttp": "",
        "fallback": True,
        "available": False,
        "degraded": True,
    }

    async def detect(self, text: str, source: str = "ai_traffic") -> dict:
        """Submit text to ThreatFade; transport or schema failure is degraded."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(
                    f"{self._base_url}/detect/json",
                    headers=self._headers,
                    json={"data": text, "source": source},
                )
                response.raise_for_status()
                result = response.json()
            if (
                not isinstance(result, dict)
                or not isinstance(result.get("detected"), bool)
                or "z_outlier" not in result
            ):
                return {**self._DEGRADED_RESPONSE, "error": "invalid_response_schema"}
            try:
                z_outlier = float(result["z_outlier"])
            except (TypeError, ValueError):
                return {**self._DEGRADED_RESPONSE, "error": "invalid_z_outlier"}
            if not math.isfinite(z_outlier):
                return {**self._DEGRADED_RESPONSE, "error": "invalid_z_outlier"}
            result["z_outlier"] = z_outlier
            result.setdefault("available", True)
            result.setdefault("degraded", False)
            logger.info(
                "threatfade_detection",
                detected=result.get("detected"),
                confidence=result.get("confidence"),
                z_outlier=result.get("z_outlier"),
                source=source,
            )
            return result
        except httpx.TimeoutException:
            logger.warning("threatfade_timeout_fallback", source=source)
            return {**self._DEGRADED_RESPONSE, "error": "timeout"}
        except httpx.ConnectError:
            logger.warning("threatfade_unreachable_fallback", source=source)
            return {**self._DEGRADED_RESPONSE, "error": "unreachable"}
        except httpx.HTTPStatusError as exc:
            logger.error("threatfade_http_error", status=exc.response.status_code)
            return {**self._DEGRADED_RESPONSE, "error": "http_status_error"}
        except (httpx.HTTPError, ValueError):
            logger.error("threatfade_transport_or_json_error", source=source)
            return {**self._DEGRADED_RESPONSE, "error": "transport_or_json_error"}
        except Exception as exc:
            logger.error("threatfade_unexpected_error", error_type=type(exc).__name__)
            return {**self._DEGRADED_RESPONSE, "error": "unexpected_error"}


    async def health(self) -> bool:
        """Check ThreatFade service liveness without leaking connection errors."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self._base_url}/health")
                return response.status_code == 200
        except Exception:
            return False



# Module-level singleton
threatfade = ThreatFadeClient()
