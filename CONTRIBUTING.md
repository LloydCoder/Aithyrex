# Contributing to Aithyrex

Thank you for helping improve Aithyrex. Contributions should preserve security boundaries and distinguish implemented behavior from independently verified effectiveness.

## Before opening an issue or pull request

1. Search existing issues and pull requests for duplicates.
2. For bugs, include the version or commit, Python version, environment, minimal reproduction and expected versus observed behavior.
3. Never publish credentials, access tokens, raw customer prompts/completions, personal data, production telemetry or sensitive exploit details. Use [SECURITY.md](SECURITY.md) for vulnerabilities.
4. For detection changes, include benign hard negatives and adversarial regression cases where appropriate. Synthetic fixtures do not establish production effectiveness.
5. For changes affecting authentication, tenancy, response, billing, evidence, telemetry or integrations, describe the trust boundary and failure behavior.

## Development setup

Requirements: Python 3.12+, Git, and Docker with the Compose plugin for the full local stack.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r backend/requirements.txt
cp .env.example .env
```

The example environment and Compose configuration are for local development only.

## Checks

Run relevant checks from the repository root:

```bash
pytest backend/tests/unit/ -v --tb=short
pytest backend/tests/integration/ -v --tb=short
ruff check backend/
bandit -r backend/ -ll -x backend/tests/
python -m backend.evaluation.red_team_suite
```

CI is authoritative for checks configured in the workflow. If a check cannot be run locally, say so instead of claiming it passed. The synthetic red-team suite is a regression check, not a production-effectiveness evaluation.

## Pull-request expectations

- Keep changes focused and explain the reason for the change.
- Add or update tests for behavior changes and failure paths.
- Update docs and changelog when externally observable behavior or support changes.
- Identify security, privacy, tenant-isolation and migration impact.
- Link relevant evidence without exposing sensitive data.
- Preserve the rule that Aithyrex findings are signals, not authorization grants.
- Do not weaken release gates or add unverified metrics, certifications, screenshots or deployment claims.

A maintainer may request changes, narrow scope or decline contributions that weaken security boundaries or cannot be verified.

## License

Contributions are submitted under the repository's Apache-2.0 license, subject to applicable law and its terms.
