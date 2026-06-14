#!/usr/bin/env bash
#
# Live agent run for the Devpost demo video.
#
# Targets VANKO-001 (held-out FOR500 case). Converges in 2 iterations
# (iter 1 65.8% → iter 2 100.0%, ~$1.75 / ~26 min wall). Self-correction
# sequence is visible between iter 1 and iter 2.
#
# Usage:
#   1. Start OBS recording (F9).
#   2. Run this script.
#   3. When the validator prints "Convergence: 0 demoted claims. Stopping."
#      and the loop exits, stop OBS (F9).
#
# Pre-reqs: see docs/DEMO_SCRIPT.md "Pre-record checklist".

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ ! -f "$HOME/.anthropic_key" ]]; then
    echo "FATAL: ~/.anthropic_key not found." >&2
    exit 1
fi
if [[ ! -d /cases/find-evil-test4 ]]; then
    echo "FATAL: /cases/find-evil-test4 not present." >&2
    exit 1
fi

export ANTHROPIC_API_KEY="$(cat "$HOME/.anthropic_key")"

# venv activation (optional — works either way).
if [[ -f .venv/bin/activate ]]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
fi

# Show the invocation on-screen for the intro shot (~3 s).
clear
cat <<'EOF'
─────────────────────────────────────────────────────────────────
 SIFT-OWL v2 — VANKO-001 (FOR500 "Abducted Zebrafish", held-out)
─────────────────────────────────────────────────────────────────
EOF
sleep 3

exec python -m eval.agents.sift_owl_v2.run_loop \
    --case            test4-vanko \
    --prompt-file     eval/agents/sift_owl_v2/prompt-test4-vanko.md \
    --model           sonnet \
    --max-budget-usd  5.00 \
    --max-iterations  3
