import json
from pathlib import Path

from scripts.assurance.check_release_readiness import evaluate_release_readiness

REPO_ROOT = Path(__file__).resolve().parents[3]
VALID_SHA = "a" * 40


def passing_manifest():
    return {
        "schema_version": 1,
        "project": "Aithyrex",
        "release_candidate_sha": VALID_SHA,
        "gates": [
            {
                "id": "CI",
                "name": "CI",
                "status": "passed",
                "release_blocking": True,
                "evidence": [
                    {
                        "type": "workflow",
                        "reference": "https://github.com/LloydCoder/Aithyrex/actions/runs/123",
                    }
                ],
            }
        ],
    }


def test_repository_release_manifest_fails_closed_on_missing_external_evidence():
    path = REPO_ROOT / "docs/assurance/release-evidence.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    report = evaluate_release_readiness(manifest, VALID_SHA, REPO_ROOT)

    assert report["ready"] is False
    blocked = {gate["id"] for gate in report["blocking_gates"]}
    assert {
        "AI_TEXT_EFFECTIVENESS",
        "INDEPENDENT_SECURITY_REVIEW",
        "PRODUCTION_DEPLOYMENT",
        "BACKUP_RESTORE_DRILL",
        "SLO_MEASUREMENT",
        "REGULATORY_CLAIMS_REVIEW",
    }.issubset(blocked)


def test_all_passed_gates_with_matching_candidate_and_evidence_are_ready():
    report = evaluate_release_readiness(passing_manifest(), VALID_SHA, REPO_ROOT)
    assert report["ready"] is True
    assert report["blocking_gates"] == []
    assert report["passed_gate_ids"] == ["CI"]


def test_candidate_sha_mismatch_blocks_release():
    report = evaluate_release_readiness(passing_manifest(), "b" * 40, REPO_ROOT)
    assert report["ready"] is False
    assert any("does not match" in issue for issue in report["issues"])


def test_passed_gate_without_evidence_is_not_accepted():
    manifest = passing_manifest()
    manifest["gates"][0]["evidence"] = []
    report = evaluate_release_readiness(manifest, VALID_SHA, REPO_ROOT)
    assert report["ready"] is False
    assert any("passed gate has no evidence" in issue for issue in report["issues"])


def test_repository_evidence_path_cannot_escape_repository():
    manifest = passing_manifest()
    manifest["gates"][0]["evidence"] = [{"type": "repo_file", "reference": "../outside.txt"}]
    report = evaluate_release_readiness(manifest, VALID_SHA, REPO_ROOT)
    assert report["ready"] is False
    assert any("stay inside the repository" in issue for issue in report["issues"])


def test_non_object_manifest_is_rejected_without_exception():
    report = evaluate_release_readiness([], VALID_SHA, REPO_ROOT)
    assert report["ready"] is False
    assert report["issues"] == ["manifest must be a JSON object"]


def test_invalid_unhashable_gate_status_is_rejected_without_exception():
    manifest = passing_manifest()
    manifest["gates"][0]["status"] = ["passed"]
    report = evaluate_release_readiness(manifest, VALID_SHA, REPO_ROOT)
    assert report["ready"] is False
    assert any("invalid status" in issue for issue in report["issues"])
