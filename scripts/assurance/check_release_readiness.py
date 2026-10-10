#!/usr/bin/env python3
"""Fail-closed release-readiness evaluator for Aithyrex.

This checks evidence references and explicit gate states. It does not certify
security, detector accuracy, regulatory compliance, or production readiness.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

VALID_STATUSES = {"passed", "blocked", "not_started", "waived"}
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_TOP_LEVEL = {"schema_version", "project", "release_candidate_sha", "gates"}


def evaluate_release_readiness(
    manifest: dict[str, Any],
    candidate_sha: str | None,
    repo_root: Path,
) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        return {
            "ready": False,
            "project": None,
            "candidate_sha": candidate_sha,
            "passed_gate_ids": [],
            "blocking_gates": [],
            "issues": ["manifest must be a JSON object"],
            "total_gates": 0,
        }

    issues: list[str] = []
    blocking_gates: list[dict[str, str]] = []
    passed_gates: list[str] = []

    missing_keys = sorted(REQUIRED_TOP_LEVEL - set(manifest))
    if missing_keys:
        issues.append("manifest missing required keys: " + ", ".join(missing_keys))

    if type(manifest.get("schema_version")) is not int or manifest.get("schema_version") != 1:
        issues.append("schema_version must be 1")

    declared_sha = manifest.get("release_candidate_sha")
    if not isinstance(declared_sha, str) or not SHA_PATTERN.fullmatch(declared_sha):
        issues.append("release_candidate_sha must be a 40-character lowercase commit SHA")
    if not isinstance(candidate_sha, str) or not SHA_PATTERN.fullmatch(candidate_sha):
        issues.append("a valid --candidate-sha is required for release evaluation")
    elif declared_sha != candidate_sha:
        issues.append("release_candidate_sha does not match --candidate-sha")

    gates = manifest.get("gates")
    if not isinstance(gates, list) or not gates:
        issues.append("gates must be a non-empty list")
        gates = []

    seen_ids: set[str] = set()
    for gate in gates:
        if not isinstance(gate, dict):
            issues.append("each gate must be an object")
            continue

        gate_id = gate.get("id")
        name = gate.get("name", gate_id or "unnamed gate")
        if not isinstance(gate_id, str) or not gate_id.strip():
            issues.append("each gate requires a non-empty id")
            continue
        if gate_id in seen_ids:
            issues.append(f"duplicate gate id: {gate_id}")
        seen_ids.add(gate_id)

        status = gate.get("status")
        release_blocking = gate.get("release_blocking", True)
        evidence = gate.get("evidence", [])

        if not isinstance(status, str) or status not in VALID_STATUSES:
            issues.append(f"{gate_id}: invalid status")
            status = "blocked"
        if not isinstance(release_blocking, bool):
            issues.append(f"{gate_id}: release_blocking must be boolean")
            release_blocking = True
        if not isinstance(evidence, list):
            issues.append(f"{gate_id}: evidence must be a list")
            evidence = []

        evidence_errors: list[str] = []
        for index, item in enumerate(evidence):
            if not isinstance(item, dict):
                evidence_errors.append(f"evidence item {index + 1} is not an object")
                continue
            evidence_type = item.get("type")
            reference = item.get("reference")
            if not isinstance(reference, str) or not reference.strip():
                evidence_errors.append(f"evidence item {index + 1} has no reference")
                continue
            if evidence_type == "workflow":
                parsed = urlparse(reference)
                if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username or parsed.password:
                    evidence_errors.append(f"evidence item {index + 1} must be a GitHub HTTPS URL")
                evidence_sha = item.get("commit_sha")
                if not isinstance(evidence_sha, str) or not SHA_PATTERN.fullmatch(evidence_sha):
                    evidence_errors.append(f"evidence item {index + 1} must include a valid commit_sha")
                elif evidence_sha != candidate_sha:
                    evidence_errors.append(f"evidence item {index + 1} commit_sha does not match candidate SHA")
            elif evidence_type == "repo_file":
                relative_path = Path(reference)
                if relative_path.is_absolute() or ".." in relative_path.parts:
                    evidence_errors.append(f"evidence path must stay inside the repository: {reference}")
                    continue
                try:
                    root_resolved = repo_root.resolve()
                    resolved_path = (repo_root / relative_path).resolve()
                except (OSError, RuntimeError):
                    evidence_errors.append(f"evidence path cannot be resolved safely: {reference}")
                    continue
                if root_resolved not in resolved_path.parents:
                    evidence_errors.append(f"evidence path resolves outside the repository: {reference}")
                elif not resolved_path.is_file():
                    evidence_errors.append(f"evidence file does not exist: {reference}")
            elif not isinstance(evidence_type, str) or evidence_type not in {
                "review",
                "dataset",
                "deployment",
                "restore",
                "metrics",
                "artifact",
                "external",
            }:
                evidence_errors.append(f"evidence item {index + 1} has an unsupported type")
            else:
                evidence_sha = item.get("candidate_sha")
                if not isinstance(evidence_sha, str) or not SHA_PATTERN.fullmatch(evidence_sha):
                    evidence_errors.append(f"evidence item {index + 1} must include a candidate_sha")
                elif evidence_sha != candidate_sha:
                    evidence_errors.append(f"evidence item {index + 1} candidate_sha does not match candidate SHA")

        if status == "passed" and not evidence:
            evidence_errors.append("passed gate has no evidence")
        if status == "passed" and evidence_errors:
            issues.extend(f"{gate_id}: {error}" for error in evidence_errors)

        if release_blocking and (status != "passed" or evidence_errors):
            reason = status if status != "passed" else "invalid evidence"
            blocking_gates.append({"id": gate_id, "name": str(name), "reason": reason})
        elif status == "passed" and not evidence_errors:
            passed_gates.append(gate_id)

    ready = not issues and not blocking_gates
    return {
        "ready": ready,
        "project": manifest.get("project"),
        "candidate_sha": candidate_sha,
        "passed_gate_ids": passed_gates,
        "blocking_gates": blocking_gates,
        "issues": issues,
        "total_gates": len(gates),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "docs/assurance/release-evidence.json",
    )
    parser.add_argument("--candidate-sha", default=None, help="exact 40-character release candidate commit SHA")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()

    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Cannot read release manifest: {type(exc).__name__}", file=sys.stderr)
        return 2

    repo_root = Path(__file__).resolve().parents[2]
    report = evaluate_release_readiness(manifest, args.candidate_sha, repo_root)
    if args.candidate_sha:
        try:
            actual_head = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo_root,
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            report["issues"].append("unable to verify checked-out Git HEAD")
            report["ready"] = False
        else:
            if actual_head != args.candidate_sha:
                report["issues"].append("candidate SHA does not match checked-out Git HEAD")
                report["ready"] = False
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    elif report["ready"]:
        print("Aithyrex release gates passed for candidate " + str(args.candidate_sha))
    else:
        print("Aithyrex release BLOCKED")
        for gate in report["blocking_gates"]:
            print(f"- {gate['id']}: {gate['reason']}")
        for issue in report["issues"]:
            print(f"- issue: {issue}")
    return 0 if report["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
