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
                        "commit_sha": VALID_SHA,
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


def test_malformed_evidence_type_is_rejected_without_exception():
    manifest = passing_manifest()
    manifest["gates"][0]["evidence"] = [{"type": ["workflow"], "reference": "x"}]
    report = evaluate_release_readiness(manifest, VALID_SHA, REPO_ROOT)
    assert report["ready"] is False
    assert any("unsupported type" in issue for issue in report["issues"])


def test_boolean_schema_version_is_not_accepted_as_integer_one():
    manifest = passing_manifest()
    manifest["schema_version"] = True
    report = evaluate_release_readiness(manifest, VALID_SHA, REPO_ROOT)
    assert report["ready"] is False
    assert any("schema_version must be 1" in issue for issue in report["issues"])


def test_duplicate_gate_ids_block_release():
    manifest = passing_manifest()
    manifest["gates"].append(dict(manifest["gates"][0]))
    report = evaluate_release_readiness(manifest, VALID_SHA, REPO_ROOT)
    assert report["ready"] is False
    assert any("duplicate gate id" in issue for issue in report["issues"])


def test_cli_reports_current_manifest_as_blocked(monkeypatch, capsys):
    import sys

    from scripts.assurance.check_release_readiness import main

    monkeypatch.setattr(sys, "argv", ["check_release_readiness.py", "--candidate-sha", VALID_SHA])
    exit_code = main()
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Aithyrex release BLOCKED" in captured.out


def test_workflow_evidence_for_another_commit_blocks_release():
    manifest = passing_manifest()
    manifest["gates"][0]["evidence"][0]["commit_sha"] = "b" * 40
    report = evaluate_release_readiness(manifest, VALID_SHA, REPO_ROOT)
    assert report["ready"] is False
    assert any("commit_sha does not match candidate SHA" in issue for issue in report["issues"])


def test_cli_accepts_complete_external_manifest_for_checked_out_sha(tmp_path, monkeypatch, capsys):
    import subprocess
    import sys

    from scripts.assurance.check_release_readiness import main

    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    ).stdout.strip()
    manifest = passing_manifest()
    manifest["release_candidate_sha"] = head
    manifest["gates"][0]["evidence"][0]["commit_sha"] = head
    manifest_path = tmp_path / "release-evidence.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "check_release_readiness.py",
            "--manifest",
            str(manifest_path),
            "--candidate-sha",
            head,
        ],
    )

    exit_code = main()
    assert exit_code == 0
    assert "release gates passed" in capsys.readouterr().out


def test_external_review_evidence_must_name_the_candidate_sha():
    manifest = passing_manifest()
    manifest["gates"][0]["evidence"] = [
        {"type": "review", "reference": "review-report-123"}
    ]
    report = evaluate_release_readiness(manifest, VALID_SHA, REPO_ROOT)
    assert report["ready"] is False
    assert any("must include a candidate_sha" in issue for issue in report["issues"])


def test_external_review_evidence_with_matching_candidate_sha_is_accepted():
    manifest = passing_manifest()
    manifest["gates"][0]["evidence"] = [
        {
            "type": "review",
            "reference": "review-report-123",
            "candidate_sha": VALID_SHA,
            "sha256": "c" * 64,
        }
    ]
    report = evaluate_release_readiness(manifest, VALID_SHA, REPO_ROOT)
    assert report["ready"] is True


def test_external_evidence_without_sha256_digest_is_rejected():
    manifest = passing_manifest()
    manifest["gates"][0]["evidence"] = [
        {
            "type": "review",
            "reference": "review-report-123",
            "candidate_sha": VALID_SHA,
        }
    ]
    report = evaluate_release_readiness(manifest, VALID_SHA, REPO_ROOT)
    assert report["ready"] is False
    assert any("SHA-256 digest" in issue for issue in report["issues"])
