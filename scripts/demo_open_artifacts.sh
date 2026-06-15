#!/usr/bin/env bash
#
# Opens the eight artifacts the demo edit cuts to (2 from setup phase,
# 6 from the 3-iteration run phase).
#
# Each `bat` invocation is a separate paged view: scroll to the section
# you want on-screen, F9 to stop OBS recording, q to quit bat, F9 to
# start OBS for the next clip.
#
# Usage:
#   bash scripts/demo_open_artifacts.sh                # defaults to test4-vanko
#   bash scripts/demo_open_artifacts.sh vanko-demo     # case-id from demo_setup.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CASE_ID="${1:-test4-vanko}"
CASE_YAML="eval/cases/${CASE_ID}/case.yaml"
PROMPT_FILE="eval/agents/sift_owl_v2/prompt-${CASE_ID}.md"

RUN_DIR="$(ls -d "eval/results/${CASE_ID}/sift-owl-v2/"*-sonnet 2>/dev/null | sort | tail -n 1)"
if [[ -z "$RUN_DIR" || ! -d "$RUN_DIR" ]]; then
    echo "FATAL: no v2 run dir found under eval/results/${CASE_ID}/. Did demo_run.sh finish?" >&2
    exit 1
fi

if ! command -v bat >/dev/null 2>&1 && ! command -v batcat >/dev/null 2>&1; then
    echo "FATAL: bat not installed. sudo apt install -y bat" >&2
    exit 1
fi

# bat alias on Ubuntu/Debian is /usr/bin/batcat.
BAT="$(command -v bat || command -v batcat)"

clips=(
    "case.yaml (scaffold)     → scene 3"  "$CASE_YAML"
    "prompt-${CASE_ID}.md     → scene 4"  "$PROMPT_FILE"
    "iter 1 validator report  → scene 7"  "$RUN_DIR/iterations/iter_1/validator_report.md"
    "iter 2 prompt (flagged)  → scene 8"  "$RUN_DIR/iterations/iter_2/prompt.md"
    "iter 2 validator report  → scene 10" "$RUN_DIR/iterations/iter_2/validator_report.md"
    "iter 3 prompt (flagged)  → scene 11" "$RUN_DIR/iterations/iter_3/prompt.md"
    "iter 3 validator report  → scene 13" "$RUN_DIR/iterations/iter_3/validator_report.md"
    "final report (REPORT.md) → scene 14" "$RUN_DIR/REPORT.md"
)

for ((i=0; i < ${#clips[@]}; i+=2)); do
    label="${clips[i]}"
    file="${clips[i+1]}"

    if [[ ! -f "$file" ]]; then
        echo "missing: $file — skipping" >&2
        continue
    fi

    echo
    echo "──────────────────────────────────────────────────────"
    echo " Next clip: $label"
    echo " File:      $file"
    echo "──────────────────────────────────────────────────────"
    echo " 1. Start OBS (F9)."
    echo " 2. Press ENTER here to open the file."
    echo " 3. Scroll to the section the script calls out."
    echo " 4. Press q to close, then F9 to stop OBS."
    read -r -p " > " _
    case "$file" in
        *.yaml|*.yml) lang=yaml ;;
        *)            lang=markdown ;;
    esac
    printf '\n$ bat --paging=always --language=%s %s\n\n' "$lang" "$file"
    "$BAT" --paging=always --style=plain --language="$lang" "$file"
done

echo
echo "All eight cutaway clips queued. Done."
