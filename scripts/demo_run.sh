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
#
# Usage:
#   bash scripts/demo_run.sh                  # defaults to test4-vanko
#   bash scripts/demo_run.sh vanko-demo       # case-id scaffolded by demo_setup.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CASE_ID="${1:-test4-vanko}"
PROMPT_FILE="eval/agents/sift_owl_v2/prompt-${CASE_ID}.md"
CASE_YAML="eval/cases/${CASE_ID}/case.yaml"

if [[ ! -f "$HOME/.anthropic_key" ]]; then
    echo "FATAL: ~/.anthropic_key not found." >&2
    exit 1
fi
if [[ ! -f "$CASE_YAML" ]]; then
    echo "FATAL: $CASE_YAML not present — run scripts/demo_setup.sh first." >&2
    exit 1
fi
if [[ ! -f "$PROMPT_FILE" ]]; then
    echo "FATAL: $PROMPT_FILE not present." >&2
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
cat <<EOF
─────────────────────────────────────────────────────────────────
 SIFT-OWL v2 — case: ${CASE_ID}
 prompt:                ${PROMPT_FILE}
─────────────────────────────────────────────────────────────────
EOF
sleep 3

exec python -m eval.agents.sift_owl_v2.run_loop \
    --case            "$CASE_ID" \
    --prompt-file     "$PROMPT_FILE" \
    --model           sonnet \
    --max-budget-usd  5.00 \
    --max-iterations  3
