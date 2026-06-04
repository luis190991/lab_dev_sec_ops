#!/usr/bin/env bash
# Codespaces post-create setup — each step is independent so one failure
# doesn't leave the container in recovery mode.
set -euo pipefail

echo "==> [1/3] Installing Python dependencies..."
pip install --no-cache-dir -q \
    flask==3.0.3 \
    flask-cors==4.0.1 \
    "PyJWT==2.8.0" \
    bandit==1.7.9 \
    requests==2.32.3

echo "==> [2/3] Installing Semgrep (may take a minute)..."
pip install --no-cache-dir -q semgrep || echo "  [WARN] semgrep install failed — SAST will use Bandit only"

echo "==> [3/3] Seeding lab database..."
python app/backend/init_db.py

chmod +x scripts/run_sast.sh

echo ""
echo "✔  Setup complete."
echo "   Start the API:  python app/backend/app.py"
echo "   Run SAST:       bash scripts/run_sast.sh"
echo "   Run DAST:       python scripts/run_dast.py"
