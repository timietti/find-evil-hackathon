#!/usr/bin/env bash
#
# Live "case scaffolding" capture for the Devpost demo video.
#
# Launches Claude Code with prompts/setup-new-case.md loaded and
# pre-feeds it the case briefing line. Claude then:
#   1. Walks /cases/find-evil-test4/
#   2. SHA-256 hashes every evidence file (chain of custody)
#   3. Classifies each (disk_image, case_briefing, triage_collection)
#   4. Reads the GPT partition table
#   5. Writes eval/cases/vanko-demo/case.yaml + case.md
#      + eval/agents/sift_owl_v2/prompt-vanko-demo.md
#
# Usage:
#   1. Start OBS recording (F9).
#   2. Run this script.
#   3. When Claude prints "Case registered: vanko-demo …", F9 to stop.
#
# Cost: ~$0.10 of Anthropic spend. Wall: ~5–10 min (sha256sum of the
# 116 GiB E01 chain dominates).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

CASE_ID="${1:-vanko-demo}"
EVIDENCE_DIR="${2:-/cases/find-evil-test4}"

if [[ ! -f "$HOME/.anthropic_key" ]]; then
    echo "FATAL: ~/.anthropic_key not found." >&2
    exit 1
fi
if [[ ! -d "$EVIDENCE_DIR" ]]; then
    echo "FATAL: evidence dir $EVIDENCE_DIR not present." >&2
    exit 1
fi
if [[ ! -f prompts/setup-new-case.md ]]; then
    echo "FATAL: prompts/setup-new-case.md not present." >&2
    exit 1
fi

export ANTHROPIC_API_KEY="$(cat "$HOME/.anthropic_key")"

# Intro card for the recording.
clear
cat <<EOF
─────────────────────────────────────────────────────────────────
 SIFT-OWL — Case scaffolding via Claude Code
 Evidence:  $EVIDENCE_DIR
 Case-id:   $CASE_ID
─────────────────────────────────────────────────────────────────
EOF
sleep 3

BRIEFING="The evidence is at $EVIDENCE_DIR. \
Briefly: A single-host insider IP theft on a Microsoft Surface 3. Call the case '$CASE_ID'."

# Echo the command on-screen for the viewer.
printf '$ cat prompts/setup-new-case.md - | claude --model sonnet\n'
printf '  (followed by:  %s)\n\n' "$BRIEFING"

# Compose the input Claude sees: the setup prompt, then the case
# briefing. Claude reads stdin, follows the setup prompt's
# instructions, and acts autonomously.
{
    cat prompts/setup-new-case.md
    echo
    echo "---"
    echo
    echo "$BRIEFING"
} | exec claude --model sonnet
