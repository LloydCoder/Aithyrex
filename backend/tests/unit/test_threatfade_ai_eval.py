from backend.evaluation.threatfade_ai_eval import evaluate_records, wilson_interval


def corpus(per_class_per_source=100, false_positives_per_source=0, missed_malicious_per_source=0):
    records = []
    sample = 0
    for source in ("prompt", "completion", "tool_output"):
        for i in range(per_class_per_source):
            sample += 1
            records.append({"sample_id": f"s-{sample}", "source": source, "label": "benign", "detected": i < false_positives_per_source})
        for i in range(per_class_per_source):
            sample += 1
            records.append({"sample_id": f"s-{sample}", "source": source, "label": "malicious", "detected": i >= missed_malicious_per_source})
    return records


def test_wilson_interval_is_bounded_and_ordered():
    low, high = wilson_interval(50, 100)
    assert 0.0 <= low < 0.5 < high <= 1.0


def test_evaluation_passes_only_with_sufficient_per_source_evidence():
    report = evaluate_records(corpus())
    assert report["status"] == "pass"
    assert report["sample_count"] == 600
    assert set(report["by_source"]) == {"prompt", "completion", "tool_output"}


def test_evaluation_fails_on_high_false_positive_rate():
    report = evaluate_records(corpus(false_positives_per_source=10))
    assert report["status"] == "fail"
    assert "false-positive upper" in report["reason"]


def test_evaluation_fails_on_low_recall_confidence_bound():
    report = evaluate_records(corpus(missed_malicious_per_source=15))
    assert report["status"] == "fail"
    assert "recall lower" in report["reason"]


def test_evaluation_requires_representative_source_and_class_coverage():
    report = evaluate_records(corpus(per_class_per_source=10))
    assert report["status"] == "insufficient_data"


def test_evaluation_rejects_raw_content_fields():
    import pytest
    records = corpus()
    records[0]["prompt"] = "do not persist raw prompt text"
    with pytest.raises(ValueError, match="unsupported fields"):
        evaluate_records(records)


def test_evaluation_rejects_duplicate_sample_ids():
    import pytest
    records = corpus()
    records[1]["sample_id"] = records[0]["sample_id"]
    with pytest.raises(ValueError, match="Duplicate sample_id"):
        evaluate_records(records)


def test_calibration_requires_explicit_risk_probabilities():
    records = corpus()
    for record in records:
        record["risk_probability"] = 0.1 if record["label"] == "benign" else 0.9
    report = evaluate_records(records)
    for metrics in report["by_source"].values():
        assert metrics["calibration"]["status"] == "evaluated"
        assert metrics["calibration"]["brier_score"] < 0.02
        assert metrics["calibration"]["expected_calibration_error_10_bins"] < 0.1


def test_unlabeled_probability_values_are_not_assumed_calibrated():
    report = evaluate_records(corpus())
    assert all(item["calibration"]["status"] == "not_evaluated" for item in report["by_source"].values())


def test_invalid_risk_probability_is_rejected():
    import pytest
    records = corpus()
    records[0]["risk_probability"] = 1.5
    with pytest.raises(ValueError, match="risk_probability must be between 0 and 1"):
        evaluate_records(records)


def test_cli_records_corpus_hash_baseline_and_non_approval(tmp_path, capsys):
    import json
    from backend.evaluation.threatfade_ai_eval import main

    records = []
    index = 0
    for source in ("prompt", "completion", "tool_output"):
        for label, detected, probability in (("benign", False, 0.1), ("malicious", True, 0.9)):
            index += 1
            records.append({
                "sample_id": f"sample-{index}", "source": source, "label": label,
                "detected": detected, "risk_probability": probability,
            })
    corpus_path = tmp_path / "candidate.jsonl"
    baseline_path = tmp_path / "baseline.jsonl"
    payload = "".join(json.dumps(record) + "\n" for record in records)
    corpus_path.write_text(payload, encoding="utf-8")
    baseline_path.write_text(payload, encoding="utf-8")

    result = main([
        str(corpus_path), "--baseline", str(baseline_path),
        "--dataset-id", "fixture", "--dataset-version", "v1",
        "--labeling-method", "two-reviewer-consensus-v1",
        "--labeler-agreement", "0.95", "--independent-review-id", "review-record-1",
        "--min-per-class-per-source", "1", "--max-fpr", "1", "--min-recall", "0",
    ])
    output = json.loads(capsys.readouterr().out)
    assert result == 0
    assert len(output["provenance"]["prediction_corpus_sha256"]) == 64
    assert output["baseline"]["prediction_corpus_sha256"]
    assert output["release_gate"]["evidence_complete_for_independent_review"] is True
    assert output["release_gate"]["release_approved"] is False
