# Protocol SIFT baseline

Drives **vanilla** Claude Code (Protocol SIFT global config + skill files installed at
`~/.claude/`) against a case in `eval/cases/<case_id>/`. The number we beat with SIFT-OWL.

## What it captures

| File | Purpose |
|---|---|
| `transcript.jsonl` | Raw `claude -p --output-format stream-json` output — every assistant message, tool call, tool result, and the final result event (token usage + cost) |
| `tool_calls.jsonl` | One JSON row per tool call extracted from the transcript |
| `final_response.md` | Concatenated text blocks — the agent's final report |
| `summary.json` | Wall clock, exit code, tool count, result event |
| `run_meta.json` | Pre/post evidence hashes, claude version, harness git rev, full invocation |

## Pre/post evidence hash check

Hashes every evidence file in `case.yaml` before and after the run. If post-run hashes
differ → spoliation. Skip with `--skip-post-hash` (saves ~5 min per 18 GB image).

## Usage

```bash
source .venv/bin/activate
python -m eval.baselines.protocol_sift.run --case rocba-001 --model sonnet \\
    --max-budget-usd 5 --max-turns 80
```

Add `--dry-run` to print the planned invocation without spending credits.

## Why this is the right baseline

The hackathon Devpost says: *"Protocol SIFT works. It also hallucinates more than we'd like."*
Our submission must demonstrate accuracy improvements over **that** baseline. To do so
honestly we have to:

1. Run vanilla Protocol SIFT (no SIFT-OWL config) on the **same** case data.
2. Score its output against ground truth — same scorer used on SIFT-OWL.
3. Diff the two — that delta is the accuracy report's main result.

The harness explicitly does not customise the case template — see the Devpost claim that
practitioners often deploy Protocol SIFT and don't fully customise per-case. That said,
we DO inject the case briefing as the user prompt so the comparison isn't unfair.

## Caveats

- The harness depends on Protocol SIFT being installed (`~/.claude/CLAUDE.md`,
  `~/.claude/settings.json`, and the five skill files under `~/.claude/skills/`).
  Verify with `ls ~/.claude/skills/`.
- Stream-json from `claude -p` may emit partial messages with `--include-partial-messages`;
  `tool_calls.jsonl` is parsed from the full assistant messages only.
