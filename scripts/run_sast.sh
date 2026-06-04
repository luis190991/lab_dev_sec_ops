#!/usr/bin/env bash
# run_sast.sh — Static Application Security Testing
# Tools: Bandit (Python AST scanner) + Semgrep (semantic grep, OWASP rules)
set -euo pipefail

BACKEND="app/backend"
REPORTS="reports/sast"
mkdir -p "$REPORTS"

echo "========================================"
echo " SAST — Security Static Analysis"
echo "========================================"

# ---- 1. Bandit ---------------------------------------------------------------
echo ""
echo ">>> [1/2] Bandit (Python security linter)"
echo "----------------------------------------"

if ! command -v bandit &>/dev/null; then
  echo "Installing bandit..."
  pip install --quiet bandit
fi

bandit \
  --recursive "$BACKEND" \
  --severity-level low \
  --confidence-level low \
  --format json \
  --output "$REPORTS/bandit.json" \
  || true   # bandit exits non-zero when issues found; don't abort

bandit \
  --recursive "$BACKEND" \
  --severity-level low \
  --confidence-level low \
  2>&1 | tee "$REPORTS/bandit.txt" || true

echo ""
echo "   Report saved: $REPORTS/bandit.json"

# ---- 2. Semgrep --------------------------------------------------------------
echo ""
echo ">>> [2/2] Semgrep (OWASP Top-10 ruleset)"
echo "----------------------------------------"

if ! command -v semgrep &>/dev/null; then
  echo "Installing semgrep..."
  pip install --quiet semgrep
fi

semgrep \
  --config "p/python" \
  --config "p/owasp-top-ten" \
  --config "p/jwt" \
  --output "$REPORTS/semgrep.json" \
  --json \
  "$BACKEND" \
  || true

semgrep \
  --config "p/python" \
  --config "p/owasp-top-ten" \
  --config "p/jwt" \
  "$BACKEND" \
  2>&1 | tee "$REPORTS/semgrep.txt" || true

echo ""
echo "   Report saved: $REPORTS/semgrep.json"

# ---- Summary -----------------------------------------------------------------
echo ""
echo "========================================"
echo " SAST complete. Check reports/sast/"
echo "========================================"
