# SIFT-OWL — Autonomous DFIR Agent for SANS SIFT

> **Submission for [FIND EVIL!](https://find-evil.devpost.com/)** — SANS hackathon, Jun 15 2026.
>
> Codename: **SIFT-OWL** — *Operate, Witness, Learn*.

## Status

Active development. See [`plans/MASTER_PLAN.md`](plans/MASTER_PLAN.md) for the strategy and weekly milestones.

### What ships today

- **38 typed read-only MCP tools** over a FastMCP stdio server (`sift-mcp`). The agent connected to it has **no shell, no filesystem, no network** — it can only call the registered forensic functions.
- **Self-correcting agent loop** (`eval/agents/sift_owl_v2/run_loop.py`). The agent generates a report; a validator scores every claim against parsed tool output; the loop replans for the next iteration with the flagged claims spelled out. Terminates on convergence, no-improvement, or max-iter cap. `--llm-check` auto-enables when `ANTHROPIC_API_KEY` is in env (Haiku rescue on Unverifiable verdicts, ~$0.05/3-iter run).
- **Validator v6** — rule-based extraction (PIDs, IPs, paths, timestamps, hashes, inodes) with paren-aware negation handling, timestamp prefix matching, and an inline LLM prose-check pass (Haiku 4.5) for unverifiable prose claims. Multi-tag bullet-list paragraphs scope each trailing `(exec_id ...)` cite to its own claim (W3-52); backticked exec-ids no longer leak into the verifiable-token list (W3-50).
- **Per-call audit trail** — `audit/exec_log.jsonl` records every MCP call with `exec_id`, args, sha256 of inputs and raw output, `parsed_summary`, `wall_ms`. Every "confirmed" claim in a final report cites an `exec_id` that the validator can resolve.
- **Iterative wire-size shrink** for multi-section tools (SRUM / Amcache / persistence_keys): if the default 50-rows-per-section payload exceeds Claude's tool-result transport envelope, the truncate-fn re-runs at 25, 12, 6, 3, 1 rows/section until it fits under ~25 KB; falls back to count-only if even cap=1 is too big. Full row data stays on disk, drillable via `query_rows`.
- **Vol3 fully offline** — the bootstrap caches the community Windows symbol pack (~800 MB) under `/opt/sift-owl/vol3-symbols/`; the MCP wrapper passes it via `-s` to every `vol` call. No Microsoft Symbol Server round-trip per case; cold-start `windows.info` drops ~30 s → ~5 s on x64 images.
- **284 unit tests** + slow E2E tests. Architectural trust boundaries (TB1-TB7) have tests asserting them.

### MCP tool inventory

| Domain | Tools |
|---|---|
| **Memory (Vol3)** — 17 | `vol3_image_info`, `vol3_psscan`, `vol3_pstree`, `vol3_cmdline`, `vol3_netscan`, `vol3_filescan`, `vol3_malfind`, `vol3_svcscan`, `vol3_userassist`, `vol3_dlllist`, `vol3_handles`, `vol3_scheduled_tasks`, `vol3_hashdump`, `vol3_cachedump`, `vol3_skeleton_key_check`, `vol3_envars`, `vol3_vadyarascan` |
| **Disk (Sleuth Kit + EWF)** — 6 | `ewf_info`, `ewf_verify`, `tsk_partition_table`, `tsk_fs_stat`, `tsk_fls_list`, `tsk_icat_extract` |
| **Windows artifacts (EZ Tools + libscca + libesedb + Python)** — 10 | `ezt_mft_parse`, `ezt_shimcache_parse`, `ezt_evtx_parse`, `ezt_amcache_parse`, `ezt_prefetch_parse` (via libyal `libscca`; PECmd is Linux-broken), `ezt_jumplist_parse`, `ezt_recyclebin_parse`, `ezt_srum_parse` (via libyal `libesedb`; SrumECmd is Linux-broken), `ezt_task_xml_parse`, `ezt_persistence_keys_parse` |
| **Threat hunt + carving + hashing** — 4 | `yara_scan_extract`, `bulk_extract`, `strings_extract`, `hash_file` |
| **Drill helper** — 1 | `query_rows` (re-parse + filter any prior call's full row list by `exec_id`) |

`sift-mcp inspect` prints the inventory. EZ Tools take an `extract_exec_id` (output of a prior `tsk_icat_extract`) instead of a filesystem path — the agent has no way to point a parser at an arbitrary file.

### Headline result

| Case | Held-out | Best v2-loop strict-verified | Notes |
|---|---|---|---|
| ROCBA-001 (memory-only) | yes (v1 single-pass) | **91.7%** (iter 3, v4) | First end-to-end case; single-pass v1 scored 57.1 % |
| ROCBA-001 (disk + memory, W3-58) | no | **96.7%** (iter 3) | C: drive image added 2026-06-08; surpasses the prior memory-only record with a larger scope |
| STARK-APT-001 (disk + memory) | yes (v1) | **86.1%** (iter 3) | 4-host case; full convergence, 0 partial / 0 failed |
| SHIELDBASE (disk + memory) | yes (single-shot 71.4 %) | **89.9%** (iter 3, W3-52) | SANS FOR508 / CRIMSON OSPREY, 15+ Win10 hosts / 198 GB. Variance band 60–92 % across 4 v2-loop samples |
| VANKO-001 (physical disk) | yes (W3-59 single-shot 36.4 %) | **100.0%** ⭐ (iter 2, W3-61) | SANS FOR500 "Abducted Zebrafish". First perfect strict-verified score; W3-61 is the post-W3-60 retry, +63.6 pp over the held-out single-shot after a prompt-side fix |

SHIELDBASE is the SANS FOR508 / CRIMSON OSPREY case — 15+ Win10 hosts, 198 GB across memory and disk. **VANKO-001** is the SANS FOR500 "Abducted Zebrafish" — Anthony Vanko / Stark Enterprises IP-theft case, single-host Surface 3 physical disk (116 GiB, GPT). Both arrived in the final week before the submission deadline as new evidence sets.

The v2 loop's strict-verified peak on SHIELDBASE has been sampled four times under varying configurations, bracketing the variance band at **60.0–92.0 %** (full per-run detail in [`docs/ACCURACY_REPORT.md`](docs/ACCURACY_REPORT.md)). The substantive findings — the actual incident narrative — reproduce across every run; the single-number score sits on top of that floor.

## What this is

An autonomous, agentic AI forensics investigator that runs on the SANS SIFT Workstation and processes raw case data (disk images, memory captures) end-to-end without human checkpoints. It improves on the baseline [Protocol SIFT](https://github.com/teamdfir/protocol-sift) configuration along every judging axis:

| Concern | Protocol SIFT (baseline) | SIFT-OWL |
|---|---|---|
| Tool surface | `Bash(*)` allow-list with narrow deny-list | Custom MCP server exposing only typed read-only forensic functions |
| Evidence integrity | Prompt-based ("Never modify `/cases/`") | Architectural — path allow-list at MCP boundary; no shell to bypass |
| Audit trail | Single `$CONVERSATION_SUMMARY` line per session | Per-call JSONL with `exec_id`, hashes, parsed_summary |
| Hallucinations | Caught only by humans | Validator agent — every "confirmed" claim must cite an `exec_id` whose parsed output supports it |
| Context bloat | Single agent reads all raw output | MCP server parses + truncates at the wire; full rows on disk, drillable via `query_rows` |
| Self-correction | None | Persistent learning loop with validator feedback in the next iteration's prompt |

![Architecture diagram](docs/architecture.png)

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the system design and trust boundaries.

## Quick start

```bash
git clone https://github.com/timietti/find-evil-hackathon.git
cd find-evil-hackathon
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Optional but recommended on a fresh SIFT image: YARA + ssdeep +
# libscca + libesedb + the Vol3 community symbol pack (~800 MB,
# lets Vol3 run fully offline). Idempotent.
bash scripts/bootstrap_sift_tools.sh

# Inspect the MCP tool inventory (no Vol3 / evidence required)
sift-mcp inspect

# Validate the test suite passes on your machine (279 tests pass)
pytest -x --deselect tests/test_disk_e2e.py \
          --deselect tests/test_vol3_memory_e2e.py \
          --deselect tests/test_ez_tools_e2e.py

# Optional: set ANTHROPIC_API_KEY so the v2 loop auto-enables
# --llm-check (Haiku rescue on Unverifiable verdicts, ~$0.05/3-iter run).
export ANTHROPIC_API_KEY=sk-ant-api03-...
```

Full installation / setup: [`INSTALL.md`](INSTALL.md).
**Judges:** see [`JUDGES.md`](JUDGES.md) — self-contained
10-step runbook for executing the agent against your own
evidence directory.

## Running an investigation

SIFT-OWL ships four bundled cases under `eval/cases/`. Each has a
`case.yaml` (machine-readable evidence inventory) + `case.md` (human
briefing) + a matching prompt in `eval/agents/sift_owl_v2/`:

| Case | Evidence path | Prompt file |
|---|---|---|
| `rocba-001` | `/cases/find-evil-test/` (memory + disk) | `prompt-rocba-001.md` |
| `test2-stark-apt` | `/cases/find-evil-test2/` (4 hosts, memory + disk) | `prompt-test2-stark-apt-v3.md` |
| `test3-shieldbase` | `/cases/find-evil-test3/` (SHIELDBASE, 15+ hosts) | `prompt-test3-shieldbase.md` |
| `test4-vanko` | `/cases/find-evil-test4/` (VANKO physical disk) | `prompt-test4-vanko.md` |

The v2 self-correction loop is the canonical runner:

```bash
python -m eval.agents.sift_owl_v2.run_loop \
    --case            rocba-001 \
    --prompt-file     eval/agents/sift_owl_v2/prompt-rocba-001.md \
    --model           sonnet \
    --max-budget-usd  5.00 \
    --max-iterations  3
```

It writes a timestamped run directory under
`eval/results/<case>/sift-owl-v2/<UTC>-<model>/` with:

```
audit/exec_log.jsonl          # every MCP call (exec_id, args, hashes, parsed_summary, wall_ms)
audit/raw/<sha256>            # content-addressed raw tool output
iterations/iter_N/
  prompt.md                   # what the agent saw this iter (incl. flagged claims from N-1)
  final_response.md           # the agent's tagged report
  validator_report.{md,json}  # per-claim verdicts + strict-verified score
final_response.md             # the best report across iterations
run_meta.json                 # command line, model, total cost, total wall
```

Loop terminates on convergence (0 demoted claims), no-improvement,
or `--max-iterations` (default 3) / `--max-budget-usd` (default 10).
`--llm-check` auto-enables when `ANTHROPIC_API_KEY` is set; pass
`--no-llm-check` to force pure rule-based validation. `--dry-run`
checks the case + prompt + evidence hashes without spawning the
investigator.

Useful side tools:

```bash
# Inspect the MCP tool inventory + per-tool docstrings
sift-mcp inspect

# Re-validate any prior run (rule-based only; or pass --llm-check)
sift-validate eval/results/rocba-001/sift-owl-v2/<run-dir>/

# Run the MCP server standalone (e.g. to attach a different client)
sift-mcp serve
```

### Your own case

Drop the evidence under `/cases/<your-case>/`, create
`eval/cases/<your-case>/case.yaml` (use any of the four bundled
ones as a template — `case_id`, `evidence_dir`, `evidence:` list
with `path` + `kind` + `sha256` per file), write a
`prompt-<your-case>.md` describing investigation goals and the
case-specific context, then invoke `run_loop` as above. The
harness will pre-hash every `evidence:` entry and refuse to start
if a hash drifts (chain of custody).

## Repo layout

```
find-evil-hackathon/
├── plans/MASTER_PLAN.md            # strategy + weekly plan
├── docs/ARCHITECTURE.md            # system design + trust boundaries
├── mcp_server/                     # custom MCP server (typed forensic functions)
│   ├── server.py                   # FastMCP stdio server
│   ├── tools/                      # memory.py, disk.py, ez_tools.py
│   ├── parsers/                    # raw tool output → structured JSON
│   └── audit.py                    # per-call JSONL writer
├── agents/
│   └── validator/                  # rule-based + LLM hallucination detector
├── eval/
│   ├── cases/                      # case.yaml + case.md per dataset
│   ├── baselines/protocol_sift/    # vanilla Claude Code baseline harness
│   ├── agents/sift_owl_v0..v2/     # SIFT-OWL eval harnesses (single-pass → loop)
│   └── results/                    # per-run validator reports + REPORT.md
├── audit/                          # default per-run audit dir (gitignored)
├── tests/                          # 284 unit tests + slow E2E
└── scripts/                        # bootstrap + one-off helpers
```

## License

MIT — see [LICENSE](LICENSE).
