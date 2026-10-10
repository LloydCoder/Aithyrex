"""Offline red-team regression suite for deterministic Aithyrex text detectors.

This harness deliberately excludes ThreatFade-dependent detectors: network-traffic
signals do not establish AI-text detection accuracy, and the suite must be runnable
without network access or production credentials.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

from backend.detectors.credential_leak import CredentialLeakDetector
from backend.detectors.data_poisoning import DataPoisoningDetector
from backend.detectors.prompt_injection import PromptInjectionDetector

DEFAULT_DATASET = Path(__file__).parent / "datasets" / "red_team_v1.jsonl"
SOURCES = {"prompt", "completion", "tool_output"}
LABELS = {"benign", "malicious"}
DETECTORS = {"prompt_injection", "credential_leak", "data_poisoning"}
MAX_CASE_TEXT_CHARS = 200_000
MAX_DATASET_BYTES = 5_000_000
MAX_CASES = 10_000
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ALLOWED_FIELDS = {"case_id", "family", "source", "label", "text", "expected_detectors"}

# Placeholders keep secret-shaped synthetic test material out of the repository and
# secret-scanning rules. Rendered values are fake and exist only in process memory.
_SYNTHETIC_TEMPLATES = {
    "[GENERATE_PAYSTACK_TEST_KEY]": "sk_live_" + ("X" * 40),
    "[GENERATE_AWS_TEST_KEY]": "AKIA" + ("A" * 16),
    "[GENERATE_PRIVATE_KEY_BLOCK]": (
        "-----BEGIN PRIVATE KEY-----\nSYNTHETIC-TEST-ONLY-NOT-A-KEY\n"
        "-----END PRIVATE KEY-----"
    ),
    "[GENERATE_BEARER_TOKEN]": "Bearer " + ("X" * 48),
    "[GENERATE_ANTHROPIC_TEST_KEY]": "sk-ant-" + ("X" * 50),
    "[GENERATE_REPEATED_CONTEXT_OVERFLOW]": "A" * 640,
}


def _render_synthetic_text(text: str) -> str:
    for placeholder, generated in _SYNTHETIC_TEMPLATES.items():
        text = text.replace(placeholder, generated)
    if "[GENERATE_" in text:
        raise ValueError("Unknown synthetic red-team placeholder")
    return text


def load_cases(path: Path) -> tuple[list[dict[str, Any]], str]:
    """Load and validate JSONL cases, returning validated records and file SHA-256."""
    raw = path.read_bytes()
    if len(raw) > MAX_DATASET_BYTES:
        raise ValueError("Dataset exceeds maximum allowed byte size")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.decode("utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on dataset line {line_number}") from exc
        if not isinstance(record, dict):
            raise ValueError(f"Dataset line {line_number} must be a JSON object")
        records.append(record)
        if len(records) > MAX_CASES:
            raise ValueError("Dataset exceeds maximum allowed case count")
    _validate_cases(records)
    return records, hashlib.sha256(raw).hexdigest()


def _validate_cases(cases: list[dict[str, Any]]) -> None:
    seen: set[str] = set()
    for index, case in enumerate(cases, start=1):
        if not isinstance(case, dict):
            raise ValueError(f"Case {index} must be a JSON object")
        extra = set(case) - ALLOWED_FIELDS
        missing = ALLOWED_FIELDS - set(case)
        if extra or missing:
            raise ValueError(
                f"Case {index} schema mismatch; missing={sorted(missing)}, extra={sorted(extra)}"
            )
        case_id = case["case_id"]
        if not isinstance(case_id, str) or not SAFE_IDENTIFIER.fullmatch(case_id):
            raise ValueError(f"Case {index} has invalid case_id")
        if case_id in seen:
            raise ValueError(f"Duplicate case_id at case {index}")
        seen.add(case_id)
        if not isinstance(case["family"], str) or not SAFE_IDENTIFIER.fullmatch(case["family"]):
            raise ValueError(f"Case {index} has invalid family")
        if not isinstance(case["source"], str) or case["source"] not in SOURCES:
            raise ValueError(f"Case {index} has unsupported source")
        if not isinstance(case["label"], str) or case["label"] not in LABELS:
            raise ValueError(f"Case {index} label must be benign or malicious")
        if not isinstance(case["text"], str) or not case["text"] or len(case["text"]) > MAX_CASE_TEXT_CHARS:
            raise ValueError(f"Case {index} has invalid text length")
        expected = case["expected_detectors"]
        if not isinstance(expected, list) or any(
            not isinstance(name, str) or name not in DETECTORS for name in expected
        ):
            raise ValueError(f"Case {index} has invalid expected_detectors")
        if len(expected) != len(set(expected)):
            raise ValueError(f"Case {index} has duplicate expected detector names")
        if case["label"] == "malicious" and not expected:
            raise ValueError(f"Malicious case {case_id} must name expected detectors")
        if case["label"] == "benign" and expected:
            raise ValueError(f"Benign case {case_id} must not require detections")


async def _evaluate_case(
    case: dict[str, Any],
    *,
    prompt_detector: PromptInjectionDetector,
    credential_detector: CredentialLeakDetector,
    poisoning_detector: DataPoisoningDetector,
) -> dict[str, Any]:
    text = _render_synthetic_text(case["text"])
    prompt = text if case["source"] == "prompt" else ""
    completion = text if case["source"] in {"completion", "tool_output"} else None

    results = await asyncio.gather(
        prompt_detector.detect(prompt=prompt),
        credential_detector.detect(prompt=prompt, completion=completion),
        poisoning_detector.detect(prompt=prompt, completion=completion),
    )
    observed = sorted(result.detector for result in results if result.detected)
    expected = sorted(case["expected_detectors"])
    missing = sorted(set(expected) - set(observed))
    return {
        "case_id": case["case_id"],
        "family": case["family"],
        "source": case["source"],
        "label": case["label"],
        "detected": bool(observed),
        "observed_detectors": observed,
        "expected_detectors": expected,
        "missing_expected_detectors": missing,
    }


def _group_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    malicious = [row for row in rows if row["label"] == "malicious"]
    benign = [row for row in rows if row["label"] == "benign"]
    expected_total = sum(len(row["expected_detectors"]) for row in malicious)
    expected_hits = expected_total - sum(len(row["missing_expected_detectors"]) for row in malicious)
    return {
        "malicious_samples": len(malicious),
        "benign_samples": len(benign),
        "malicious_detected": sum(row["detected"] for row in malicious),
        "benign_flagged": sum(row["detected"] for row in benign),
        "malicious_recall": (
            sum(row["detected"] for row in malicious) / len(malicious) if malicious else None
        ),
        "benign_false_positive_rate": (
            sum(row["detected"] for row in benign) / len(benign) if benign else None
        ),
        "expected_detector_coverage": expected_hits / expected_total if expected_total else None,
    }


def evaluate_cases(
    cases: list[dict[str, Any]],
    *,
    dataset_sha256: str,
    dataset_classification: str = "custom_unverified",
    min_malicious_recall: float = 0.90,
    max_benign_false_positive_rate: float = 0.05,
    min_expected_detector_coverage: float = 0.90,
) -> dict[str, Any]:
    """Run deterministic detectors and return content-free, reproducible metrics."""
    for value, name in (
        (min_malicious_recall, "min_malicious_recall"),
        (max_benign_false_positive_rate, "max_benign_false_positive_rate"),
        (min_expected_detector_coverage, "min_expected_detector_coverage"),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
            raise ValueError(f"{name} must be between 0 and 1")
    if dataset_classification not in {"synthetic_only", "custom_unverified"}:
        raise ValueError("dataset_classification must be synthetic_only or custom_unverified")
    if not isinstance(dataset_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", dataset_sha256):
        raise ValueError("dataset_sha256 must be a lowercase SHA-256 digest")
    _validate_cases(cases)

    async def evaluate_all() -> list[dict[str, Any]]:
        prompt_detector = PromptInjectionDetector()
        credential_detector = CredentialLeakDetector()
        poisoning_detector = DataPoisoningDetector()
        return list(await asyncio.gather(*(
            _evaluate_case(
                case,
                prompt_detector=prompt_detector,
                credential_detector=credential_detector,
                poisoning_detector=poisoning_detector,
            )
            for case in cases
        )))

    rows = asyncio.run(evaluate_all())
    metrics = _group_metrics(rows)
    by_source: dict[str, Any] = {}
    by_family: dict[str, Any] = {}
    for source in sorted(SOURCES):
        by_source[source] = _group_metrics([row for row in rows if row["source"] == source])
    for family in sorted({row["family"] for row in rows}):
        by_family[family] = _group_metrics([row for row in rows if row["family"] == family])

    reasons = []
    recall = metrics["malicious_recall"]
    false_positive_rate = metrics["benign_false_positive_rate"]
    expected_coverage = metrics["expected_detector_coverage"]
    if recall is None or recall < min_malicious_recall:
        reasons.append("malicious recall below configured threshold")
    if false_positive_rate is None or false_positive_rate > max_benign_false_positive_rate:
        reasons.append("benign false-positive rate above configured threshold")
    if expected_coverage is None or expected_coverage < min_expected_detector_coverage:
        reasons.append("expected detector coverage below configured threshold")
    if set(by_source) != SOURCES or any(
        not by_source[source]["malicious_samples"] or not by_source[source]["benign_samples"]
        for source in SOURCES
    ):
        reasons.append("each source must include malicious and benign cases")
    missing_cases = [row["case_id"] for row in rows if row["missing_expected_detectors"]]
    if missing_cases:
        reasons.append("one or more expected detector assertions were missed")

    return {
        "schema_version": "aithyrex.red-team-evaluation.v1",
        "status": "pass" if not reasons else "fail",
        "reason": reasons,
        "provenance": {
            "dataset_sha256": dataset_sha256,
            "dataset_classification": dataset_classification,
            "sample_count": len(rows),
            "detectors": sorted(DETECTORS),
            "confidence_calibrated": False,
        },
        "metrics": metrics,
        "by_source": by_source,
        "by_family": by_family,
        "missed_expected_case_ids": missing_cases,
        "case_results": rows,
        "release_gate": {
            "regression_suite_passed": not reasons,
            "release_approved": False,
            "independent_review_required": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--min-malicious-recall", type=float, default=0.90)
    parser.add_argument("--max-benign-fpr", type=float, default=0.05)
    parser.add_argument("--min-expected-detector-coverage", type=float, default=0.90)
    args = parser.parse_args(argv)
    try:
        cases, dataset_sha256 = load_cases(args.dataset)
        dataset_classification = (
            "synthetic_only" if args.dataset.resolve() == DEFAULT_DATASET.resolve()
            else "custom_unverified"
        )
        # Detector loggers may be configured with stdout handlers by the host
        # application. Keep the CLI contract machine-readable: diagnostics go to
        # stderr while the single JSON evaluation report remains on stdout.
        with redirect_stdout(sys.stderr):
            report = evaluate_cases(
                cases,
                dataset_sha256=dataset_sha256,
                dataset_classification=dataset_classification,
                min_malicious_recall=args.min_malicious_recall,
                max_benign_false_positive_rate=args.max_benign_fpr,
                min_expected_detector_coverage=args.min_expected_detector_coverage,
            )
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        print(json.dumps({"status": "invalid_dataset", "error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
