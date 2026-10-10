from unittest.mock import AsyncMock, patch

import pytest

from backend.core.shield_engine import Severity
from backend.detectors.c2_behaviour import C2BehaviourDetector
from backend.detectors.covert_channel import CovertChannelDetector


@pytest.mark.asyncio
async def test_c2_positive_is_advisory_and_mitre_taxonomy_is_separated():
    with patch(
        "backend.detectors.c2_behaviour.threatfade.detect",
        new=AsyncMock(return_value={
            "detected": True, "z_outlier": 11.0, "confidence": "high",
            "score": 0.9, "entropy": 7.1, "rules_matched": 2,
            "mitre_ttp": "T1071.001", "available": True, "degraded": False,
        }),
    ):
        result = await C2BehaviourDetector().detect("encoded agent payload")
    assert result.detected is True
    assert result.severity == Severity.MEDIUM
    assert result.details["advisory_only"] is True
    assert result.details["confidence_calibrated"] is False
    assert result.mitre_atlas == ["AML.T0043"]
    assert "T1071.001" in result.details["mitre_attack"]


@pytest.mark.asyncio
async def test_covert_channel_positive_is_advisory_and_mitre_taxonomy_is_separated():
    with patch(
        "backend.detectors.covert_channel.threatfade.detect",
        new=AsyncMock(return_value={
            "detected": False, "z_outlier": 0.2, "confidence": "info",
            "available": True, "degraded": False,
        }),
    ):
        result = await CovertChannelDetector().detect("", completion="A" * 64)
    assert result.detected is True
    assert result.details["advisory_only"] is True
    assert result.details["confidence_calibrated"] is False
    assert result.mitre_atlas == ["AML.T0048"]
    assert result.details["mitre_attack"] == ["T1027"]
