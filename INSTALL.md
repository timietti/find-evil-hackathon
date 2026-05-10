# Install / Try-It-Out

> Target: any SANS SIFT Workstation (Ubuntu x86-64) with the standard SIFT toolset already installed. Tested on SIFT 24.x with Python 3.12.

## Prerequisites

| Requirement | Notes |
|---|---|
| SANS SIFT Workstation | Volatility 3, Sleuth Kit, EWF tools, EZ Tools, Plaso, YARA, bulk_extractor pre-installed at SIFT-default paths |
| Python 3.12+ | `python3 --version` |
| Claude Code CLI | `claude --version` — the agent harness invokes `claude -p ...` |
| .NET 6 runtime | `dotnet --info` — EZ Tools require it |
| Anthropic API key | `export ANTHROPIC_API_KEY=...` (only needed for the validator's `--llm-check` mode) |
| Disk space | ≥ 5 GB free under `audit/` for one full multi-host run |

## Install

```bash
git clone https://github.com/timietti/find-evil-hackathon.git
cd find-evil-hackathon
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Optional but recommended: install the forensic-tool deps that aren't
# always present on a fresh SIFT image (YARA, Vol2, PECmd, SrumECmd,
# Memory Baseliner). Idempotent.
bash scripts/bootstrap_sift_tools.sh

# Sanity-check the install
sift-mcp inspect           # prints the 26-tool MCP inventory
pytest -x --deselect tests/test_disk_e2e.py \
          --deselect tests/test_vol3_memory_e2e.py \
          --deselect tests/test_ez_tools_e2e.py
```

The slow E2E tests under the `--deselect` flags require real evidence images. Skip them on first install; run the full suite once you have a case dir.

## Run on a case

SIFT-OWL ships three evaluation harnesses; the canonical one is the **v2 self-correction loop** under `eval/agents/sift_owl_v2/`. It expects a case definition in `eval/cases/<case_id>/case.yaml` describing evidence paths and SHA-256 hashes.

```bash
export ANTHROPIC_API_KEY=...   # required only if you want --llm-check

# Run a 3-iteration self-correction loop on the bundled ROCBA case
python -m eval.agents.sift_owl_v2.run_loop \
    --case rocba-001 \
    --prompt-file prompt.md \
    --model sonnet \
    --max-budget-usd 5 \
    --max-iterations 3

# Output:
#   eval/results/rocba-001/sift-owl-v2/<run_id>/
#     iterations/iter_{1,2,3}/
#       final_response.md         ← agent's report this iteration
#       transcript.jsonl          ← raw stream-json (gitignored)
#       validator_report.{md,json}← per-claim verdicts + score
#     audit/
#       exec_log.jsonl            ← shared across all iterations
#       raw/                      ← raw per-call outputs
```

Available case IDs (under `eval/cases/`):

- `rocba-001` — single Win10 host, 18 GB memory image (Fred Rocba IP theft scenario)
- `test2-stark-apt` — 4-host APT case, 58 GB (DC + 2 Win7 + XP)
- `test3-shieldbase` — 15-host CRIMSON OSPREY (held out for final eval)

## Validate any prior run

The validator is a standalone CLI (`sift-validate`) that reads an audit dir + `final_response.md` and emits per-claim verdicts:

```bash
sift-validate --run-dir eval/results/rocba-001/sift-owl-v2/<run_id>/iterations/iter_3

# Add LLM prose-check for unverifiable claims (~$0.01/run)
sift-validate --llm-check --llm-max-calls 30 \
    --run-dir eval/results/rocba-001/sift-owl-v2/<run_id>/iterations/iter_3
```

## Architectural enforcement

The `sift-mcp` server exposes typed read-only forensic functions only. The agent on the other end of the wire has no shell. This means an LLM cannot:

- delete, overwrite, or rename evidence files
- read/write arbitrary filesystem paths (only `extract_exec_id` references are accepted by EZ Tools)
- exfiltrate evidence (no network egress tools exposed)
- run arbitrary binaries (subprocess invocations are argv-list, never `shell=True`)

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full trust-boundary table.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `volatility3 symbols not found` | First run downloads Microsoft PDB symbols; ensure outbound HTTPS to `downloads.volatilityfoundation.org`, or pre-populate `~/.cache/volatility3/`. Win7-x86 PAE PDBs are NOT auto-downloadable — the agent flags `[GAP]` for those memory images and proceeds with disk-side analysis. |
| `dotnet: command not found` | EZ Tools require `dotnet` runtime v6 — `apt install dotnet-runtime-6.0`. |
| `vol not on PATH` | The wrapper looks up `vol` via `$PATH`. Override with `SIFT_OWL_VOL3_BIN=/path/to/vol`. |
| `MCP tool result overflow` | Each row-emitting tool truncates to 50 rows at the wire; use `query_rows(<exec_id>, filter_field, filter_value, limit, offset)` to drill into the full row list (preserved on disk). |
| Long wall-clock on large memory images | Default `--max-turns-per-iter 120`; bump for cases with many hosts. |
| `ANTHROPIC_API_KEY` not set | Required only for the validator's `--llm-check` flag and v4 prose check. Without it, the validator runs purely rule-based. |
