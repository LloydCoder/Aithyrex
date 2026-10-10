"""Offline evaluation gate for ThreatFade used on AI-interaction text."""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

REQUIRED_SOURCES = ("prompt", "completion", "tool_output")
LABELS = {"benign", "malicious"}
ALLOWED_FIELDS = {"sample_id", "source", "label", "detected", "score", "z_outlier"}


def wilson_interval(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """Return a two-sided Wilson score interval for a binomial proportion."""
    if total <= 0 or successes < 0 or successes > total or not math.isfinite(z) or z <= 0:
        raise ValueError("Require 0 <= successes <= total, total > 0 and finite z > 0")
    p = successes / total
    z2 = z * z
    denominator = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / denominator
    margin = z * math.sqrt((p * (1.0 - p) / total) + (z2 / (4.0 * total * total))) / denominator
    return max(0.0, center - margin), min(1.0, center + margin)


def _validate_records(records: list[dict[str, Any]]) -> None:
    seen: set[str] = set()
    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"Record {index} must be a JSON object")
        extra = set(record) - ALLOWED_FIELDS
        if extra:
            raise ValueError(f"Record {index} contains unsupported fields: {sorted(extra)}; raw content is prohibited")
        sample_id = record.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id or len(sample_id) > 128:
            raise ValueError(f"Record {index} has invalid sample_id")
        if sample_id in seen:
            raise ValueError(f"Duplicate sample_id: {sample_id}")
        seen.add(sample_id)
        if record.get("label") not in LABELS:
            raise ValueError(f"Record {index} label must be benign or malicious")
        if record.get("source") not in REQUIRED_SOURCES:
            raise ValueError(f"Record {index} source must be one of {REQUIRED_SOURCES}")
        if not isinstance(record.get("detected"), bool):
            raise ValueError(f"Record {index} detected must be a boolean")
        for field in ("score", "z_outlier"):
            if field in record:
                value = record[field]
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                    raise ValueError(f"Record {index} has invalid {field}")


def _source_metrics(records: list[dict[str, Any]]) -> dict[str, Any]:
    benign = [r for r in records if r["label"] == "benign"]
    malicious = [r for r in records if r["label"] == "malicious"]
    tp = sum(r["detected"] for r in malicious)
    fn = len(malicious) - tp
    fp = sum(r["detected"] for r in benign)
    tn = len(benign) - fp
    recall = tp / len(malicious) if malicious else None
    fpr = fp / len(benign) if benign else None
    precision = tp / (tp + fp) if tp + fp else 0.0
    return {
        "benign_samples": len(benign), "malicious_samples": len(malicious),
        "true_positive": tp, "false_negative": fn, "false_positive": fp, "true_negative": tn,
        "precision": precision, "recall": recall, "false_positive_rate": fpr,
        "recall_wilson_95": list(wilson_interval(tp, len(malicious))) if malicious else None,
        "false_positive_rate_wilson_95": list(wilson_interval(fp, len(benign))) if benign else None,
    }


def evaluate_records(
    records: list[dict[str, Any]],
    *,
    min_per_class_per_source: int = 100,
    max_false_positive_rate: float = 0.05,
    min_recall: float = 0.90,
) -> dict[str, Any]:
    """Evaluate labeled predictions and fail closed on missing coverage or weak confidence bounds."""
    if min_per_class_per_source < 1:
        raise ValueError("min_per_class_per_source must be at least 1")
    if not math.isfinite(max_false_positive_rate) or not 0 <= max_false_positive_rate <= 1:
        raise ValueError("max_false_positive_rate must be between 0 and 1")
    if not math.isfinite(min_recall) or not 0 <= min_recall <= 1:
        raise ValueError("min_recall must be between 0 and 1")
    _validate_records(records)
    by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_source[record["source"]].append(record)
    metrics = {source: _source_metrics(by_source[source]) for source in REQUIRED_SOURCES}
    under_sampled = [
        source for source, item in metrics.items()
        if item["benign_samples"] < min_per_class_per_source or item["malicious_samples"] < min_per_class_per_source
    ]
    if under_sampled:
        status = "insufficient_data"
        reason = "Each source needs the configured minimum for both benign and malicious samples"
    else:
        failures = []
        for source, item in metrics.items():
            if item["recall_wilson_95"][0] < min_recall:
                failures.append(f"{source}: recall lower 95% bound below {min_recall:.3f}")
            if item["false_positive_rate_wilson_95"][1] > max_false_positive_rate:
                failures.append(f"{source}: false-positive upper 95% bound above {max_false_positive_rate:.3f}")
        status = "fail" if failures else "pass"
        reason = "; ".join(failures) if failures else "All per-source confidence-bound gates passed"
    return {
        "evaluation_schema": "aithyrex.threatfade-ai-evaluation.v1",
        "status": status,
        "reason": reason,
        "sample_count": len(records),
        "gate": {
            "min_per_class_per_source": min_per_class_per_source,
            "max_false_positive_rate": max_false_positive_rate,
            "min_recall": min_recall,
            "confidence_interval": "Wilson 95%",
        },
        "by_source": metrics,
        "limitations": [
            "This measures binary predictions on the supplied labeled corpus, not confidence calibration.",
            "A pass is meaningful only if the corpus is representative, independently labeled and versioned.",
            "This tool does not automatically enable ThreatFade signals to block or vote on AI text.",
        ],
    }


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}") from exc
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path, help="Labeled JSONL predictions; raw prompt/completion text is prohibited")
    parser.add_argument("--output", type=Path, help="Optional path for the metrics-only JSON report")
    parser.add_argument("--min-per-class-per-source", type=int, default=100)
    parser.add_argument("--max-fpr", type=float, default=0.05)
    parser.add_argument("--min-recall", type=float, default=0.90)
    args = parser.parse_args(argv)
    try:
        records = load_jsonl(args.corpus)
        report = evaluate_records(records, min_per_class_per_source=args.min_per_class_per_source,
                                  max_false_positive_rate=args.max_fpr, min_recall=args.min_recall)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "invalid_corpus", "error": str(exc)}), file=sys.stderr)
        return 2
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        try:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(json.dumps({"status": "output_error", "error": str(exc)}), file=sys.stderr)
            return 2
    return 0 if report["status"] == "pass" else 1 if report["status"] == "fail" else 2


if __name__ == "__main__":
    raise SystemExit(main())
