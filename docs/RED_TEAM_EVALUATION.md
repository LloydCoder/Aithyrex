# Aithyrex Red-Team Evaluation Gate

## Purpose

This offline suite is a repeatable regression gate for deterministic Aithyrex text detectors. It exercises direct prompt injection, encoded and Unicode-obfuscated instructions, retrieval/tool-output injection, system-prompt extraction, context-overflow patterns, and synthetic credential-shaped strings. It includes benign controls to catch regressions in false-positive behavior.

The corpus is **synthetic-only**. Secret-shaped values are represented by placeholders in the committed JSONL file and rendered as fake values in process memory. The runner emits case IDs, detector IDs, metrics and a SHA-256 dataset digest; it never emits the raw test text.

## Run

From the repository root:

```bash
python -m backend.evaluation.red_team_suite
pytest -q backend/tests/unit/test_red_team_suite.py
```

Override thresholds or dataset path when conducting a controlled experiment:

```bash
python -m backend.evaluation.red_team_suite \
  --dataset backend/evaluation/datasets/red_team_v1.jsonl \
  --min-malicious-recall 0.90 \
  --max-benign-fpr 0.05 \
  --min-expected-detector-coverage 0.90
```

Exit code 0 means the regression gate passed; 1 means the corpus ran but a gate failed; 2 means the dataset or arguments were invalid. The report always sets release_approved to false and requires independent review.

## Dataset and provenance

- Dataset: `aithyrex-synthetic-red-team`, version 1.0.0.
- Current corpus: 32 cases — 20 malicious and 12 benign.
- Sources: prompt, completion and tool_output.
- Required detectors: prompt_injection, credential_leak and data_poisoning.
- Provenance manifest: [red_team_v1.manifest.json](../backend/evaluation/datasets/red_team_v1.manifest.json).
- Dataset bytes are hashed into the report so a reviewer can identify the exact evaluated corpus.

## Gate semantics

The runner calculates overall and per-source/per-family malicious recall, benign false-positive rate, and coverage of the detector IDs explicitly expected by each malicious case. The default gate requires:

- malicious recall of at least 90%;
- benign false-positive rate no higher than 5%;
- expected-detector coverage of at least 90%;
- malicious and benign examples in each source category; and
- zero missed expected-detector assertions.

The zero-miss assertion requirement is intentionally stricter than the aggregate percentage gate for the current small regression corpus. The aggregate metrics are still reported to make changes visible; they are not estimates of production performance.

## Scope and exclusions

This is a **deterministic regression suite**, not an exhaustive benchmark. It currently evaluates only local prompt-injection, credential-leak and data-poisoning detectors. ThreatFade-dependent covert-channel/C2 paths are excluded because network-traffic metrics do not establish AI-text detection accuracy and the test must remain offline. The suite does not test live model behavior, streaming, multimodal content, framework lifecycle coverage, detector calibration, production tenant behavior, or complete tool/MCP mediation.

A green result means the known synthetic cases still behave as expected. It does not establish production precision/recall, robustness against unseen attacks, regulatory compliance, or release approval.

## Standards alignment

The threat-family organization is informed by the [OWASP Artificial Intelligence Security Verification Standard (AISVS) 1.0](https://owasp.org/projects/artificial-intelligence-security-verification-standard-aisvs-docs), whose testable control areas include input validation, orchestration/agentic security, adversarial robustness, and monitoring/logging. Attack categories are also cross-referenced conceptually against the living [MITRE ATLAS](https://atlas.mitre.org/) knowledge base. These references guide test selection; this corpus is not an AISVS certification or a claim that every ATLAS technique is covered.

The [OWASP Vendor Evaluation Criteria for AI Red Teaming Providers & Tooling v1.0](https://genai.owasp.org/resource/owasp-vendor-evaluation-criteria-for-ai-red-teaming-providers-tooling-v1-0/) reinforces the need to distinguish realistic, evidence-backed testing from superficial jailbreak-only demonstrations. This suite is an initial deterministic regression layer; a separate representative, independently reviewed evaluation is required before making production detection claims.
