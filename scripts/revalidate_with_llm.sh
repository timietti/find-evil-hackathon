#!/usr/bin/env bash
# Re-validate every committed SIFT-OWL run with --llm-check enabled.
#
# Pre-req: ANTHROPIC_API_KEY must be set in your shell:
#     export ANTHROPIC_API_KEY=sk-ant-...
#
# Usage:
#     bash scripts/revalidate_with_llm.sh
#
# Cost envelope: ~$0.10 per run with unverifiable claims.
# Total across all 6 runs ≈ $0.30.

set -uo pipefail

if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    echo "ERROR: ANTHROPIC_API_KEY is not set." >&2
    echo "Set it before running this script:" >&2
    echo "  export ANTHROPIC_API_KEY=sk-ant-..." >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
source .venv/bin/activate

# All committed runs that have an audit dir + final_response.md.
RUNS=(
    "rocba-001/sift-owl-v1/20260509T174516Z-sonnet"
    "test2-stark-apt/sift-owl-v1/20260509T190900Z-sonnet"
    "test2-stark-apt/sift-owl-v1/20260509T205030Z-sonnet"
    "rocba-001/sift-owl-v2/20260510T065909Z-sonnet/iterations/iter_3"
    "test2-stark-apt/sift-owl-v2/20260510T081103Z-sonnet/iterations/iter_3"
    "test2-stark-apt/sift-owl-v2/20260510T090305Z-sonnet/iterations/iter_1"
)

TOTAL_COST=0
echo
echo "Run                                              | rule-verif | LLM  | LLM-V | LLM-U | LLM-X | LLM-? | final_score | LLM_cost"
echo "-------------------------------------------------|------------|------|-------|-------|-------|-------|-------------|---------"

for path in "${RUNS[@]}"; do
    full="$REPO_ROOT/eval/results/$path"
    if [[ ! -d "$full" ]]; then
        echo "  SKIP (missing): $path" >&2
        continue
    fi

    # Snapshot rule-verif before LLM check
    pre_rule_verif=$(python3 -c "
import json
try:
    d = json.load(open('$full/validator_report.json'))
    print(d['summary']['verified'])
except Exception:
    print('?')
" 2>/dev/null)

    sift-validate --quiet --llm-check --llm-max-calls 30 --run-dir "$full" >/dev/null 2>&1 || true

    python3 -c "
import json
d = json.load(open('$full/validator_report.json'))
s = d['summary']
print(f'{\"$path\":48s} | {$pre_rule_verif:>10} | {s[\"llm_checked\"]:>4} | {s[\"llm_verified\"]:>5} | {s[\"llm_unsupported\"]:>5} | {s[\"llm_unrelated\"]:>5} | {s[\"llm_uncertain\"]:>5} | {s[\"confirmation_score\"]*100:>10.1f}% | \${s[\"llm_total_cost_usd\"]:.4f}')
"
done

echo
echo "Done. Updated validator_report.{md,json} files in each run dir."
echo "Inspect any with:  cat eval/results/<path>/validator_report.md"
