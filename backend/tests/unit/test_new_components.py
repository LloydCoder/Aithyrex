"""
Aithyrex — Unit Tests: New Components (legacy integration compatibility)
===========================================================
Tests MITRE report generator, Olvrix bridge, and integration middleware.
"""

import json
from unittest.mock import AsyncMock, patch

import pytest


# ── MITRE Report Generator ─────────────────────────────────────────────────────
class TestMITREReport:

    def test_json_report_is_valid(self):
        from backend.core.mitre_report import generate_json
        output = generate_json()
        data = json.loads(output)
        assert "coverage" in data
        assert data["total_techniques"] > 0
        assert data["full_coverage"] == 0
        assert data["mapped_techniques"] > 0

    def test_json_has_required_fields(self):
        from backend.core.mitre_report import generate_json
        data = json.loads(generate_json())
        entry = data["coverage"][0]
        assert "technique_id" in entry
        assert "technique_name" in entry
        assert "detector" in entry
        assert "coverage_level" in entry

    def test_markdown_report_has_atlas_section(self):
        from backend.core.mitre_report import generate_markdown
        md = generate_markdown()
        assert "MITRE ATLAS mappings" in md
        assert "AML.T0051" in md
        assert "prompt_injection" in md

    def test_markdown_report_has_attck_section(self):
        from backend.core.mitre_report import generate_markdown
        md = generate_markdown()
        assert "ATT&CK" in md
        assert "T1552" in md
        assert "credential_leak" in md

    def test_csv_report_has_header(self):
        from backend.core.mitre_report import generate_csv
        csv_out = generate_csv()
        assert "technique_id" in csv_out
        assert "AML.T0051" in csv_out

    def test_all_detectors_covered(self):
        from backend.core.mitre_report import COVERAGE_MAP
        detectors = {e.detector for e in COVERAGE_MAP}
        required = {
            "prompt_injection", "credential_leak",
            "covert_channel", "c2_behaviour", "data_poisoning",
        }
        for req in required:
            assert any(req in d for d in detectors), f"Detector {req} missing from MITRE coverage"

    def test_full_coverage_techniques_present(self):
        from backend.core.mitre_report import COVERAGE_MAP
        mapped = {e.technique_id: e for e in COVERAGE_MAP}
        assert "AML.T0051" in mapped
        assert "T1552" in mapped
        assert "T1027" in mapped
        assert all(e.coverage_level == "heuristic" for e in COVERAGE_MAP)

    def test_validation_baseline_in_markdown(self):
        from backend.core.mitre_report import generate_markdown
        md = generate_markdown()
        assert "No AI-text detection accuracy" in md
        assert "false-positive rate" in md
        assert "14.76" not in md
        assert "490,000" not in md


# ── Olvrix Bridge ──────────────────────────────────────────────────────────────
class TestOlvrixBridge:

    @pytest.fixture
    def bridge(self):
        from olvrix_bridge.ai_shield_sync import AIShieldSync
        return AIShieldSync()

    @pytest.mark.asyncio
    async def test_empty_html_passes_safely(self, bridge):
        result = await bridge.handle_business_scraped("", "biz-001")
        assert result["safe"] is True

    @pytest.mark.asyncio
    async def test_no_api_key_fails_closed(self, bridge):
        """Missing inspection configuration must not silently pass content."""
        result = await bridge.handle_business_scraped(
            "<html><body>Normal business site</body></html>",
            "biz-001",
        )
        assert result["safe"] is False
        assert result["degraded"] is True
        assert result["reason"] == "inspection_unavailable"

    @pytest.mark.asyncio
    async def test_timeout_fails_closed(self, bridge):
        """Network timeout must be visible as a degraded block."""
        import httpx
        with patch("olvrix_bridge.ai_shield_sync.AITHYREX_API_URL", "https://api.example.test"), patch(
            "olvrix_bridge.ai_shield_sync.AITHYREX_API_TOKEN", "test-session-token"
        ), patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=httpx.TimeoutException("timeout")
            )
            result = await bridge.handle_business_scraped("some html", "biz-002")
        assert result["safe"] is False
        assert result["degraded"] is True
        assert result["reason"] == "inspection_unavailable"

    @pytest.mark.asyncio
    async def test_connection_error_fails_closed(self, bridge):
        """Aithyrex unreachable must be visible as a degraded block."""
        import httpx
        with patch("olvrix_bridge.ai_shield_sync.AITHYREX_API_URL", "https://api.example.test"), patch(
            "olvrix_bridge.ai_shield_sync.AITHYREX_API_TOKEN", "test-session-token"
        ), patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = AsyncMock(
                side_effect=httpx.ConnectError("unreachable")
            )
            result = await bridge.handle_website_generated("generated html", "biz-003")
        assert result["safe"] is False
        assert result["degraded"] is True
        assert result["reason"] == "inspection_unavailable"

    @pytest.mark.asyncio
    async def test_escalation_threshold(self, bridge):
        """Z-score below threshold should not escalate."""
        result = await bridge.handle_security_event(
            threatfade_result={"z_outlier": 3.0, "confidence": "low", "mitre_ttp": ""},
            business_id="biz-004",
        )
        assert result["escalated"] is False

    @pytest.mark.asyncio
    async def test_high_z_score_triggers_escalation(self, bridge):
        """Z-score above threshold should trigger escalation."""
        with patch.object(bridge, "_call_shield", new=AsyncMock(
            return_value={"action": "block", "severity": "high", "blocked": True, "detections": []}
        )), patch.object(bridge, "_escalate_to_fusionops", new=AsyncMock()):
            result = await bridge.handle_security_event(
                threatfade_result={"z_outlier": 12.5, "confidence": "high", "mitre_ttp": "T1071.001"},
                business_id="biz-005",
            )
        assert result["escalated"] is True

    @pytest.mark.asyncio
    async def test_outreach_message_scanned(self, bridge):
        """Outreach messages must be scanned before sending."""
        with patch.object(bridge, "_call_shield", new=AsyncMock(
            return_value={"action": "pass", "severity": "clean", "blocked": False, "detections": []}
        )):
            result = await bridge.handle_outreach_generated(
                message="Hello! We noticed your business...",
                channel="whatsapp",
                business_id="biz-006",
            )
        assert result["safe"] is True


# ── LlamaIndex Middleware ──────────────────────────────────────────────────────
class TestLlamaIndexMiddleware:

    def test_observer_initializes(self):
        from integrations.llamaindex_middleware import AIShieldObserver
        obs = AIShieldObserver(api_key="", raise_on_block=False)
        assert obs is not None

    def test_observer_handles_empty_llm_start(self):
        from integrations.llamaindex_middleware import AIShieldObserver
        obs = AIShieldObserver(api_key="", raise_on_block=False)
        obs.on_llm_start({}, [])   # Should not raise

    def test_observer_inspects_prompt_without_shared_state(self):
        from integrations.llamaindex_middleware import AIShieldObserver
        obs = AIShieldObserver(api_key="", raise_on_block=False)
        with patch.object(obs, "_check") as check:
            obs.on_llm_start({}, ["What is the capital of France?"])
        check.assert_called_once_with(prompt="What is the capital of France?")

    def test_observer_inspects_completion_without_cross_request_pairing(self):
        from integrations.llamaindex_middleware import AIShieldObserver
        obs = AIShieldObserver(api_key="", raise_on_block=False)
        with patch.object(obs, "_check") as check:
            obs.on_llm_end(type("Response", (), {"text": "answer"})())
        check.assert_called_once_with(prompt="", completion="answer")

    def test_observer_handles_retrieve_empty(self):
        from integrations.llamaindex_middleware import AIShieldObserver
        obs = AIShieldObserver(api_key="", raise_on_block=False)
        obs.on_retrieve([])   # Should not raise


# ── AutoGen Middleware ─────────────────────────────────────────────────────────
class TestAutoGenMiddleware:

    def test_unsupported_autogen_adapter_refuses_construction(self):
        from integrations.autogen_middleware import ShieldedConversableAgent

        with pytest.raises(NotImplementedError, match="not supported"):
            ShieldedConversableAgent(name="test-agent", raise_on_block=False)

    def test_unsupported_crewai_adapter_refuses_construction(self):
        from integrations.autogen_middleware import ShieldedCrewTask

        with pytest.raises(NotImplementedError, match="not supported"):
            ShieldedCrewTask(description="Normal task description", raise_on_block=False)
