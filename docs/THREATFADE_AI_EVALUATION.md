# ThreatFade AI-text evaluation gate

## Current status

**AI-text detection is not yet validated.** ThreatFade's network-traffic Z-score and confidence buckets must not be interpreted as calibrated AI-text risk. In Aithyrex, ThreatFade-backed C2/covert-channel findings remain visible but advisory-only. They do not drive block/alert policy or cast a Parliament vote. ThreatFade transport/schema loss remains degraded and fail-closed.

## Offline evaluation

Prepare a labeled JSONL corpus of predictions for AI-interaction text. Store only labels and numeric/boolean predictions; never include raw prompts, completions, tool outputs, secrets, personal data, or free-text explanations.

Each row must contain:

```json
{"sample_id":"unique-id","source":"prompt","label":"benign","detected":false,"score":0.03,"z_outlier":0.2,"risk_probability":0.04}
```

Allowed `source` values are `prompt`, `completion`, and `tool_output`; `label` is `benign` or `malicious`. `score` and `z_outlier` are optional finite metadata and are **not** treated as probabilities. `risk_probability` is optional and must be a finite value in [0, 1]; calibration metrics are emitted only when every sample for a source includes it. Sample IDs must be unique; unknown fields are rejected so raw content cannot be silently carried into reports.

Run a numeric evaluation:

```bash
python -m backend.evaluation.threatfade_ai_eval ./candidate.jsonl --output ./metrics.json
```

For a provenance-rich comparison, include an immutable baseline over the same sample IDs and labels, dataset metadata, measured labeler agreement, and an independent-review record reference:

```bash
python -m backend.evaluation.threatfade_ai_eval ./candidate.jsonl \
  --baseline ./baseline.jsonl \
  --dataset-id "non-sensitive-dataset-id" \
  --dataset-version "v1.2.0" \
  --labeling-method "two-reviewer-consensus-v1" \
  --labeler-agreement 0.95 \
  --independent-review-id "review-record-reference" \
  --output ./metrics.json
```

The report includes SHA-256 fingerprints of candidate/baseline prediction files, UTC evaluation time, per-source confusion metrics, baseline deltas, and Brier/ECE calibration metrics when explicit probabilities are supplied. The report never asserts that caller-provided provenance or review references have been independently verified. `release_gate.release_approved` is always false; approval remains a separate human assurance decision.

The default gate requires at least 100 benign and 100 malicious samples per source, recall lower 95% Wilson confidence bound at least 90%, and false-positive-rate upper 95% Wilson bound at most 5% for each source. Exit code 0 means the supplied dataset passed those numeric gates; exit code 1 means it failed; exit code 2 means the corpus is invalid or under-sampled.

A passing report alone does not activate enforcement. Before changing `advisory_only` or `confidence_calibrated`, require dataset provenance, labeler agreement, versioned corpus hash, subgroup/source analysis, an independent review, and an explicit change to the enforcement policy with regression tests. No representative corpus is shipped in this repository, so no accuracy/recall/FPR claim is made.

## Runtime contract

The HTTP client uses a bounded two-attempt retry for transient transport errors and HTTP 429/5xx responses, strict response validation, a 2.5-second per-attempt timeout, and an input-size limit. Exhausted retries, malformed fields, or upstream fallback/degraded markers return an explicit degraded result. The Shield Engine fails closed on degraded mandatory ThreatFade telemetry.

The C2/covert-channel detectors label unvalidated positives `advisory_only=true`; the aggregation policy excludes them from enforcement severity/action while preserving them in evidence. Parliament only receives a ThreatFade score when a detector explicitly marks it calibrated.

## Validation references

- [OWASP AI Security Verification Standard](https://owasp.org/www-project-ai-security-verification-standard/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)

These are evaluation/design references, not evidence that this implementation has passed independent certification.
