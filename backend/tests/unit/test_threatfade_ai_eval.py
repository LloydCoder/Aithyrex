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
