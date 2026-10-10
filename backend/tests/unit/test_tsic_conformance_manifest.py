import json
from pathlib import Path


def test_tsic_manifest_matches_versioned_receiver_contracts():
    root = Path(__file__).resolve().parents[3]
    manifest = json.loads(
        (root / "contracts/tsic/aithyrex-contracts.v1.json").read_text(encoding="utf-8")
    )

    assert manifest["schema_version"] == "tinlance.aithyrex.integration-conformance.v1"
    assert manifest["authority_boundary"]["identity_tenant_policy_approval_and_execution"] == (
        "Tinlance Agent Platform"
    )
    assert manifest["authority_boundary"]["authorization_performed"] is False
    assert manifest["authority_boundary"]["execution_performed"] is False
    assert manifest["assertion_replay_policy"]["duplicate_http_status"] == 409
    assert manifest["assertion_replay_policy"]["state_unavailable_http_status"] == 503

    route_sources = {
        "aithyrex.agent-action-signal.v1": root / "backend/api/routes/detect.py",
        "aithyrex.context-inspection.v1": root / "backend/api/routes/context.py",
        "aithyrex.behavioral-correlation.v1": root / "backend/api/routes/sequence.py",
    }
    assert {contract["contract_id"] for contract in manifest["contracts"]} == set(route_sources)

    for contract in manifest["contracts"]:
        source = route_sources[contract["contract_id"]].read_text(encoding="utf-8")
        assert f'"/{contract["path"].rsplit("/", 1)[-1]}"' in source
        assert contract["assertion_header"] in source
        assert contract["response_schema_version"] in source
        assert "assertion_replay_guard.consume" in source
