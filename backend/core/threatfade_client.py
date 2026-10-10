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

import asyncio
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

    _RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
    _MAX_ATTEMPTS = 2
    _REQUEST_TIMEOUT_SECONDS = 2.5
    _MAX_TEXT_LENGTH = 200_000
    _CONFIDENCE_BUCKETS = {"unknown", "info", "low", "medium", "high", "critical"}

    @staticmethod
    def _is_finite_number(value: object) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))

    def _validate_result(self, result: object) -> tuple[dict | None, str | None]:
        if not isinstance(result, dict) or not isinstance(result.get("detected"), bool):
            return None, "invalid_response_schema"
        if "z_outlier" not in result:
            return None, "invalid_response_schema"
        if not self._is_finite_number(result.get("z_outlier")):
            return None, "invalid_z_outlier"
        for field in ("score", "entropy"):
            if field in result and not self._is_finite_number(result[field]):
                return None, f"invalid_{field}"
        if "entropy" in result and float(result["entropy"]) < 0:
            return None, "invalid_entropy"
        if "rules_matched" in result and (
            isinstance(result["rules_matched"], bool)
            or not isinstance(result["rules_matched"], int)
            or result["rules_matched"] < 0
        ):
            return None, "invalid_rules_matched"
        if "confidence" in result:
            confidence = result["confidence"]
            if isinstance(confidence, str):
                if confidence.lower() not in self._CONFIDENCE_BUCKETS:
                    return None, "invalid_confidence"
            elif self._is_finite_number(confidence):
                if not 0.0 <= float(confidence) <= 1.0:
                    return None, "invalid_confidence"
            else:
                return None, "invalid_confidence"
        if "mitre_ttp" in result and (
            not isinstance(result["mitre_ttp"], str) or len(result["mitre_ttp"]) > 128
        ):
            return None, "invalid_mitre_ttp"
        for flag in ("fallback", "degraded", "available"):
            if flag in result and not isinstance(result[flag], bool):
                return None, f"invalid_{flag}"
        if result.get("fallback") or result.get("degraded") or result.get("available") is False:
            return None, "degraded_upstream_response"

        normalized = dict(result)
        normalized["z_outlier"] = float(result["z_outlier"])
        for field in ("score", "entropy"):
            if field in normalized:
                normalized[field] = float(normalized[field])
        normalized.setdefault("confidence", "unknown")
        normalized.setdefault("score", 0.0)
        normalized.setdefault("entropy", 0.0)
        normalized.setdefault("rules_matched", 0)
        normalized.setdefault("mitre_ttp", "")
        normalized["available"] = True
        normalized["degraded"] = False
        return normalized, None

    async def detect(self, text: str, source: str = "ai_traffic") -> dict:
        """Submit text with bounded retries; transport/schema failures remain degraded."""
        if not isinstance(text, str) or len(text) > self._MAX_TEXT_LENGTH:
            return {**self._DEGRADED_RESPONSE, "error": "invalid_or_oversized_input"}
        if not isinstance(source, str) or not source or len(source) > 64:
            return {**self._DEGRADED_RESPONSE, "error": "invalid_source"}

        try:
            async with httpx.AsyncClient(timeout=self._REQUEST_TIMEOUT_SECONDS) as client:
                for attempt in range(self._MAX_ATTEMPTS):
                    try:
                        response = await client.post(
                            f"{self._base_url}/detect/json",
                            headers=self._headers,
                            json={"data": text, "source": source},
                        )
                        if response.status_code in self._RETRYABLE_STATUS_CODES and attempt + 1 < self._MAX_ATTEMPTS:
                            await asyncio.sleep(0.1)
                            continue
                        response.raise_for_status()
                        result, validation_error = self._validate_result(response.json())
                        if validation_error:
                            logger.warning("threatfade_response_degraded", source=source, reason=validation_error)
                            return {**self._DEGRADED_RESPONSE, "error": validation_error}
                        assert result is not None
                        logger.info(
                            "threatfade_detection",
                            detected=result.get("detected"),
                            confidence=result.get("confidence"),
                            z_outlier=result.get("z_outlier"),
                            source=source,
                        )
                        return result
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code in self._RETRYABLE_STATUS_CODES and attempt + 1 < self._MAX_ATTEMPTS:
                            await asyncio.sleep(0.1)
                            continue
                        logger.error("threatfade_http_error", status=exc.response.status_code, source=source)
                        return {**self._DEGRADED_RESPONSE, "error": "http_status_error"}
                    except httpx.TransportError as exc:
                        if attempt + 1 < self._MAX_ATTEMPTS:
                            await asyncio.sleep(0.1)
                            continue
                        error = "timeout" if isinstance(exc, httpx.TimeoutException) else "unreachable" if isinstance(exc, httpx.ConnectError) else "transport_error"
                        logger.warning("threatfade_transport_degraded", source=source, error=error)
                        return {**self._DEGRADED_RESPONSE, "error": error}
                    except (ValueError, TypeError):
                        logger.warning("threatfade_json_degraded", source=source)
                        return {**self._DEGRADED_RESPONSE, "error": "invalid_json_response"}
        except Exception as exc:
            logger.error("threatfade_unexpected_error", error_type=type(exc).__name__)
            return {**self._DEGRADED_RESPONSE, "error": "unexpected_error"}
        return {**self._DEGRADED_RESPONSE, "error": "retry_exhausted"}

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
