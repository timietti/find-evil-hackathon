#!/usr/bin/env bash
#
# Opens the four post-run artifacts the demo edit cuts to.
#
# Each `bat` invocation is a separate paged view: scroll to the section
# you want on-screen, F9 to stop OBS recording, q to quit bat, F9 to
# start OBS for the next clip.
#
# By default, opens the most recent VANKO-001 v2 run. Override with:
#   bash scripts/demo_open_artifacts.sh <path-to-run-dir>

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

RUN_DIR="${1:-}"
if [[ -z "$RUN_DIR" ]]; then
    RUN_DIR="$(ls -d eval/results/test4-vanko/sift-owl-v2/*-sonnet 2>/dev/null | sort | tail -n 1)"
fi
if [[ -z "$RUN_DIR" || ! -d "$RUN_DIR" ]]; then
    echo "FATAL: no VANKO v2 run dir found. Did demo_run.sh finish?" >&2
    exit 1
fi

if ! command -v bat >/dev/null 2>&1; then
    echo "FATAL: bat not installed. sudo apt install -y bat" >&2
    exit 1
fi

# bat alias on Ubuntu/Debian is /usr/bin/batcat.
BAT="$(command -v bat || command -v batcat)"

clips=(
    "iter 1 validator report  → scene 3" "$RUN_DIR/iterations/iter_1/validator_report.md"
    "iter 2 prompt (flagged)  → scene 4" "$RUN_DIR/iterations/iter_2/prompt.md"
    "iter 2 validator report  → scene 6" "$RUN_DIR/iterations/iter_2/validator_report.md"
    "final report             → scene 7" "$RUN_DIR/final_response.md"
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
    "$BAT" --paging=always --style=plain --language=markdown "$file"
done

echo
echo "All four cutaway clips queued. Done."
