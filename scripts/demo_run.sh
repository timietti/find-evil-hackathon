#!/usr/bin/env bash
#
# Live agent run for the Devpost demo video.
#
# Targets VANKO-001 (held-out FOR500 case). Runs the full 3 iterations
# and climbs 30.0% → 52.4% → 80.0% strict-verified (demoted 14 → 10 → 4,
# tools 52 → 21 → 11; ~$2.71 / ~34 min wall). Self-correction is visible
# at both the iter1→iter2 and iter2→iter3 transitions.
#
# Usage:
#   1. Start OBS recording (F9).
#   2. Run this script.
#   3. When the loop prints "iter 3 complete: ..." then
#      "SIFT-OWL v2 run complete. → ..." and the shell prompt returns,
#      stop OBS (F9). (It does NOT print "Convergence ... Stopping." —
#      that only fires on a zero-demotion iteration; this run hits the
#      --max-iterations 3 cap instead.)
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

CMD=(
    python -m eval.agents.sift_owl_v2.run_loop
    --case            "$CASE_ID"
    --prompt-file     "$PROMPT_FILE"
    --model           sonnet
    --max-budget-usd  5.00
    --max-iterations  3
)

# Show the invocation on-screen for the intro shot (~3 s).
clear
cat <<EOF
─────────────────────────────────────────────────────────────────
 SIFT-OWL v2 — case: ${CASE_ID}
 prompt:                ${PROMPT_FILE}
─────────────────────────────────────────────────────────────────
EOF
printf '\n$ %s \\\n' "${CMD[0]} ${CMD[1]} ${CMD[2]}"
printf '    %s %s \\\n' "${CMD[3]}" "${CMD[4]}"
printf '    %s %s \\\n' "${CMD[5]}" "${CMD[6]}"
printf '    %s %s \\\n' "${CMD[7]}" "${CMD[8]}"
printf '    %s %s \\\n' "${CMD[9]}" "${CMD[10]}"
printf '    %s %s\n\n'  "${CMD[11]}" "${CMD[12]}"
sleep 3

exec "${CMD[@]}"
