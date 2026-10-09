#!/usr/bin/env bash
# AI Shield — GitHub Repo Setup Script
# ======================================
# Run this once to create the repo, push the scaffold,
# and configure branch protection.
#
# Requirements:
#   - GitHub CLI (gh) installed and authenticated
#   - git configured with your name/email
#
# Usage:
#   chmod +x scripts/setup.sh
#   ./scripts/setup.sh

set -euo pipefail

REPO="Tinlance/ai-shield"
DESCRIPTION="Runtime security for LLM and agentic AI systems"

echo "🛡️  AI Shield — Repo Setup"
echo "=========================="

# ── 1. Create GitHub repo ─────────────────────────────────────────────
echo "→ Creating GitHub repo: $REPO"
gh repo create "$REPO" \
  --public \
  --description "$DESCRIPTION" \
  --homepage "https://tinlance.com/ai-shield" \
  --add-readme=false \
  --license=apache-2.0 \
  2>/dev/null || echo "  (repo may already exist — continuing)"

# ── 2. Initialise git if needed ───────────────────────────────────────
if [ ! -d ".git" ]; then
  echo "→ Initialising git"
  git init
  git remote add origin "https://github.com/$REPO.git"
fi

# ── 3. Initial commit ─────────────────────────────────────────────────
echo "→ Committing scaffold"
git add -A
git commit -m "feat: initial scaffold — AI Shield v0.1.0

- FastAPI backend skeleton (reused from KalevioAI pattern)
- Prompt injection detector (direct patterns, MITRE AML.T0051)
- Credential leak detector (18 patterns, FDSE Identity Threat Scanner)
- Covert channel detector stub (ThreatFade entropy bridge)
- C2 behaviour detector (ThreatFade HTTP client)
- SIEM exporter: JSON / CSV / Splunk HEC / CEF / STIX 2.1
- OpenAI + Anthropic proxy interceptors
- LangChain callback middleware
- Detection rules YAML (prompt injection + credential patterns)
- Unit tests: prompt injection (12 tests) + credential leak (9 tests)
- Integration tests: ThreatFade bridge (4 tests)
- GitHub Actions CI/CD + security scan (OWASP + TruffleHog)
- Devcontainer + .env.example
- Architecture docs

60% of infrastructure reused from existing Tinlance portfolio:
ThreatFade, KalevioAI, ReconOS OFE, FDSE Toolkit, FusionOps, TwinGuard

Co-authored-by: Claude Team <claude@anthropic.com>"

# ── 4. Push ───────────────────────────────────────────────────────────
echo "→ Pushing to GitHub"
git branch -M main
git push -u origin main --force

# ── 5. Configure repo settings ────────────────────────────────────────
echo "→ Configuring repo settings"
gh repo edit "$REPO" \
  --enable-issues \
  --enable-projects \
  --delete-branch-on-merge \
  2>/dev/null || true

# ── 6. Set repo topics ────────────────────────────────────────────────
echo "→ Setting topics"
gh repo edit "$REPO" \
  --add-topic "ai-security" \
  --add-topic "llm-security" \
  --add-topic "prompt-injection" \
  --add-topic "runtime-security" \
  --add-topic "fastapi" \
  --add-topic "python" \
  --add-topic "mitre-atlas" \
  --add-topic "nis2" \
  2>/dev/null || true

echo ""
echo "✅ Done!"
echo ""
echo "Repo live at: https://github.com/$REPO"
echo ""
echo "Next steps:"
echo "  1. Add secrets to GitHub → Settings → Secrets:"
echo "     ANTHROPIC_API_KEY, THREATFADE_API_KEY, CLERK_SECRET_KEY"
echo "  2. Run: pip install -r backend/requirements.txt"
echo "  3. Copy .env.example → .env and fill in values"
echo "  4. Run tests: pytest backend/tests/unit/ -v"
echo "  5. Start Sprint 1: wire ShieldEngine detectors"
