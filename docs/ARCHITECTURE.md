# SIFT-OWL — Architecture

**Status:** v0.4 (2026-05-10) — describes the system as implemented. Sections marked *deferred* are documented choices we explicitly did not build.

## Goals

1. **Architecturally enforce evidence integrity.** The agent must be unable to modify or read-side-channel evidence even if the model misbehaves — enforced by the MCP boundary, not by prompts.
2. **Audit every finding back to a tool execution.** Every claim in the final report cites an `exec_id` resolvable from `audit/exec_log.jsonl`.
3. **Beat Protocol SIFT's accuracy and hallucination rate** on the same case data.
4. **Self-correct without human intervention** within a hard iteration cap.
5. **Stay reproducible** — another practitioner can clone, install, point at a case, and get the same kind of report.

## System diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                       SIFT-OWL self-correction loop                      │
│   eval/agents/sift_owl_v2/run_loop.py — orchestrates N iterations:       │
│   plan → execute → validate → replan-with-flagged-claims → repeat        │
└────────────────┬─────────────────────────────────────────────────────────┘
                 │ each iteration spawns:
                 ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │ Investigator subprocess: `claude -p <prompt> --mcp-config ...`    │
   │ Sonnet 4.6 — sees ONLY: the prompt + the registered MCP tools.    │
   │ Built-in Bash / Read / Edit / Write / Agent / WebFetch DENIED.    │
   └───────────────────────────────────┬───────────────────────────────┘
                                       │  MCP stdio (JSON-RPC)
                                       ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │  sift-mcp — FastMCP stdio server (mcp_server/server.py)           │
   │  20 typed read-only functions. No shell. No filesystem-by-path.   │
   │  Per-call audit row written to exec_log.jsonl before return.      │
   │  MCP-wire payload truncated to 50 rows; full data on disk.        │
   └───────────────────────────────────┬───────────────────────────────┘
                                       │  subprocess (argv list, never shell=True)
                                       ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │  SIFT tools  ·  vol3, fls, icat, ewfinfo, MFTECmd, EvtxECmd,      │
   │                 AppCompatCacheParser, AmcacheParser                │
   └─────────────────────────┬─────────────────────────────────────────┘
                             │  read-only access; paths validated against allow-list
                             ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │ Evidence:  /cases/<CASE>/    (read-only by convention; path       │
   │                              validation rejects writes/non-roots) │
   │ Audit:     audit/exec_log.jsonl + audit/raw/                      │
   │            audit/raw/extracts/<exec_id>.bin  ← tsk_icat_extract   │
   │            audit/raw/ez_tools/<exec_id>/    ← per-call subtree    │
   └───────────────────────────────────────────────────────────────────┘

After each iteration, a non-LLM validator pass runs:
  ┌────────────────────────────────────────────────────────────────────┐
  │ Validator (agents/validator/validate.py)                           │
  │   1. Segment final_response.md into per-tag claims (CONFIRMED /    │
  │      INFERRED / HYPOTHESIS / GAP)                                  │
  │   2. Resolve cited exec_id(s) → read parsed_summary from audit log │
  │   3. Extract structured tokens (PIDs, IPs, paths, timestamps, ...) │
  │   4. Verify each token is structurally present in the parsed data  │
  │   5. (Optional) `--llm-check` for unverifiable prose claims via    │
  │      Haiku 4.5 → VERIFIED / UNSUPPORTED / UNRELATED / UNCERTAIN    │
  │   6. Emit validator_report.{md,json} with per-claim verdicts       │
  └────────────────────────────────────────────────────────────────────┘
```

## Trust boundaries

| # | Boundary | Enforcement | Type | Test |
|---|---|---|---|---|
| TB1 | Agent → tool execution | MCP function whitelist; built-in `Bash` / `Read` / `Edit` / `Write` / `WebFetch` / `Agent` denied via `--disallowed-tools`; only `mcp__sift-owl__*` allow-listed | **Architectural** | `tests/test_mcp_server.py::test_mcp_server_lists_all_tools` asserts the 20-tool inventory; agent harness wires `DISALLOWED_BUILTINS` |
| TB2 | MCP server → arbitrary paths | `validate_evidence_path()` rejects paths outside the allow-list (`SIFT_OWL_EVIDENCE_ROOT`, default `/cases`); resolves symlinks; raises `PathValidationError` | **Architectural** | `tests/test_vol3_image_info.py` — path-traversal + outside-root cases |
| TB3 | Tool subprocess → shell injection | All invocations are `subprocess.run(argv_list, ...)`; **`shell=True` is never used**; argv built only from validated typed inputs | **Architectural** | grep-asserted: `grep -r "shell=True" mcp_server/` returns nothing |
| TB4 | EZ Tools → arbitrary input file | EZ Tools accept only `extract_exec_id`; `_resolve_extract()` requires the row's `tool == "tsk_icat_extract"` and the on-disk file to exist under `audit/raw/extracts/` | **Architectural** | `tests/test_ez_tools_parsers.py` + e2e tests pass only when the extract chain is honored |
| TB5 | Agent → network egress | No tool exposes HTTP/curl/wget; Vol3 PDB downloads are the only outbound traffic, handled by the subprocess at first-run | **Architectural** | Implicit — MCP inventory contains no networking primitives |
| TB6 | Claim → cited evidence | Validator parses every CONFIRMED/INFERRED claim into structured tokens; verifies each token is in the cited tool's `parsed_summary` (or LLM prose-checks the rest) | **Hybrid** (rule-based + LLM) | `tests/test_validator.py` — 54 tests including paren-aware negation, timestamp prefix matching, mocked LLM prose check |
| TB7 | Inference vs. confirmation | Agent prompts require explicit `[CONFIRMED]` / `[INFERRED]` / `[HYPOTHESIS]` / `[GAP]` tag per claim; validator demotes mismatches | **Prompt + post-hoc** | `tests/test_validator.py::test_parse_claims_*` |

**Not enforced architecturally (documented limits):**

- `chattr +i` on evidence files is not currently set; we rely on path-validation + lack of write tools in the MCP inventory. Adding `chattr +i` and `ro,noatime,noexec` bind-mounts is a future enhancement (the original v0.1 design called for this; deferred because v0.4's path-validation + tool inventory provides equivalent protection at the API boundary).
- `unshare -n` per-subprocess is not used; we rely on the MCP inventory containing no network tools.

## MCP server function inventory (implemented)

The MCP server exposes **20 typed functions**. Every function returns `{exec_id, ...parsed_dict}` and records one row in `audit/exec_log.jsonl`:

```jsonc
{ "exec_id": "01H...UUIDv7",
  "ts": "2026-05-10T18:00:00Z",
  "agent": "memory_agent",
  "tool": "vol3_psscan",
  "args": { "image": "/cases/find-evil-test2/.../mem.001" },
  "input_hash": "sha256:...",
  "output_hash": "sha256:...",
  "raw_output_path": "audit/raw/01H...",
  "exit_code": 0,
  "wall_ms": 7820,
  "summary": "112 procs; 0 hidden",
  "parsed_summary": { /* compact summary minus the bulky row list */ } }
```

The agent sees `exec_id + summary + first 50 rows`. The full row list stays on disk and is reachable via `query_rows(exec_id, filter_field, filter_value, limit, offset)`.

### Memory (Volatility 3) — 9

| Function | Wraps | Notes |
|---|---|---|
| `vol3_image_info(image)` | `windows.info` | OS / build / arch / CPU / capture timestamp |
| `vol3_psscan(image)` | `windows.psscan` | Pool-scanned procs (incl. hidden + exited) |
| `vol3_pstree(image)` | `windows.pstree` | Parent/child tree |
| `vol3_cmdline(image)` | `windows.cmdline` | Per-process command lines |
| `vol3_netscan(image)` | `windows.netscan` | TCP/UDP endpoints + foreign-IP frequency |
| `vol3_filescan(image)` | `windows.filescan` | Cached file objects |
| `vol3_malfind(image)` | `windows.malfind` | RWX / MZ-headed VAD regions |
| `vol3_svcscan(image)` | `windows.svcscan` | Service Control Manager |
| `vol3_userassist(image)` | `windows.registry.userassist` | Per-user Explorer-driven program execution |

### Disk (Sleuth Kit + EWF) — 6

| Function | Wraps |
|---|---|
| `ewf_info(image)` | `ewfinfo` (case metadata, MD5/SHA1 anchors) |
| `ewf_verify(image)` | `ewfverify` (re-reads every byte) |
| `tsk_partition_table(image)` | `mmls -i ewf` |
| `tsk_fs_stat(image, offset?)` | `fsstat -i ewf` |
| `tsk_fls_list(image, offset?)` | `fls -i ewf -r -p -F` (recursive, including deleted) |
| `tsk_icat_extract(image, inode, offset?)` | `icat` — writes to `audit/raw/extracts/<exec_id>.bin`; returns size + sha256 of extracted bytes |

`tsk_icat_extract` is **the only path into EZ Tools** — they take the resulting `exec_id`, never a filesystem path. This is TB4.

### Windows artifacts (EZ Tools) — 4

| Function | Wraps | Pre-req |
|---|---|---|
| `ezt_mft_parse(extract_exec_id)` | `MFTECmd --json` | `tsk_icat_extract(image, inode=0)` |
| `ezt_shimcache_parse(extract_exec_id)` | `AppCompatCacheParser --csv` | extract `Windows\System32\config\SYSTEM` |
| `ezt_evtx_parse(extract_exec_id)` | `EvtxECmd --json` | extract a single `.evtx` file |
| `ezt_amcache_parse(extract_exec_id)` | `AmcacheParser -i --csv` | extract `Windows\AppCompat\Programs\Amcache.hve` |

### Drill helper — 1

| Function | Purpose |
|---|---|
| `query_rows(exec_id, filter_field?, filter_value?, limit?, offset?)` | Re-parse a prior call's full row list, filter, paginate. Substring match on strings; exact on numbers/bools. |

### Deferred from the original v0.1 plan

`vol3_handles`, `vol3_dlllist`, `vol3_modscan`, `baseliner_proc_diff`, `mount_e01_ro`, `tsk_recover`, `mactime_timeline`, `parse_registry`, `extract_prefetch`, `extract_srum`, `yara_scan`, `bulk_extractor_carve`, `vol3_vadyarascan`, `plaso_extract`, `plaso_filter`, `plaso_info` — none are implemented. The 20 shipped tools cover memory + disk + the highest-signal Windows-artifact parsers; additional wrappers can be added as the SHIELDBASE eval reveals gaps.

## Audit log schemas

### `audit/exec_log.jsonl` — one row per MCP call

Schema as shown above. UUIDv7 `exec_id`s, content-addressed `raw_output_path`, parsed_summary preserves aggregates but strips bulky row lists.

### `audit/raw/` — per-call output captures

```
audit/raw/<exec_id>                  ← parser-friendly text output
audit/raw/extracts/<exec_id>.bin     ← tsk_icat_extract bytes
audit/raw/ez_tools/<exec_id>/        ← per-call EZ Tools output dir
audit/raw/subprocess/                ← stderr captures from failed invocations
```

### `audit/` shared across loop iterations

The v2 self-correction loop uses **one shared audit dir** across all iterations of a single case run. This is intentional: iteration 2 can call `query_rows(<exec_id from iter 1>)` to re-read a prior call's full output instead of re-running the tool. This is the cross-iteration memory.

## Self-correction loop (`eval/agents/sift_owl_v2/run_loop.py`)

```
iter 1: agent runs base prompt → final_response.md → validator scores
iter 2: build follow-up prompt with flagged claims + the iter-1 audit log
        agent re-investigates → new final_response.md → validator scores
iter 3: same, with iter-1 and iter-2 history visible via the shared audit log
```

**Termination conditions** (any one fires):

- `iteration >= --max-iterations` (default 3)
- cumulative cost ≥ `--max-budget-usd` (default $10)
- validator score has not improved AND no new findings → "no improvement"
- validator score = 100% strict-verified → "converged"

**Replan signal** — between iterations the harness reads `validator_report.json`, picks all `failed` and `partial` verdicts, and renders them into the next prompt as:

```
Iteration N validator flagged these claims:
  [FAILED] "STUN.exe (PID 1912) connecting to 81.30.144.115" — PID 1912 not in psscan
  [PARTIAL] "Mimikatz residue at lsass" — no malfind exec_id cited
Resolve each flagged claim in iteration N+1 by either:
  (a) collecting the missing evidence and re-asserting with correct citation, or
  (b) demoting from CONFIRMED to INFERRED/HYPOTHESIS/GAP.
```

This pattern produced **emergent self-correction** on STARK-APT-001: by iteration 3 the agent had inferred the validator's tokenization rules and was structuring claims to be machine-checkable.

## Validator versions

The validator has shipped across four iterations; each version is preserved as live code:

| Version | What it added | Trigger |
|---|---|---|
| v0 (rule-based) | Per-claim segmentation, exec_id resolution, structured-token extraction (PIDs, IPs, paths, timestamps) | Initial baseline |
| v1 | Negation detection (`not in netscan`) | ROCBA v0 had 2 "failed" claims that were correct *negative* assertions |
| v2 | Backslash normalisation (`\Users` vs `\\Users` in JSON), subject-clause negation heuristic, markdown strip pre-segmentation | Multiple false positives in ROCBA + STARK-APT v1 runs |
| v3 | Per-tag claim segmentation (hybrid: single-tag = whole paragraph; multi-tag = per-tag slice), paren-aware negation, timestamp prefix matching | STARK-APT v2 EZT run surfaced multi-tag paragraphs the v2 splitter mangled |
| **v4** | LLM-based prose check (Haiku 4.5) for unverifiable claims; opt-in via `--llm-check`; promotes/demotes based on structural support in cited tool's parsed data | Push past rule-based ceiling for prose-only claims |

All versions ship in `agents/validator/`. Tests in `tests/test_validator.py` cover every regression that drove a version bump.

## Termination & safety

- Hard caps on iterations, wall-clock-per-iter, and total budget. Each is enforced by the harness before the next iteration spawns.
- Every cap hit writes the partial state to `audit/` and emits the best-so-far report.
- All Anthropic API calls (validator v4 prose check only) require `ANTHROPIC_API_KEY` env var; the validator falls back to rule-based with a stderr warning if absent.

## Resolved open questions

1. ~~LangGraph?~~ **No.** Direct Claude Code subprocess (`claude -p`) is simpler, gives free MCP wire-protocol implementation, and lets us use the existing `--allowed-tools` / `--disallowed-tools` / `--mcp-config` switches as architectural enforcement points.
2. ~~Specialists call MCP directly or via the orchestrator?~~ **Single agent per iteration.** Multi-agent specialist setup was deferred; the single-agent + self-correction-loop pattern produced 91.7% strict-verified on ROCBA and 86.1% on STARK-APT with simple iteration replay.
3. ~~Validator: rule-based / LLM / hybrid?~~ **Hybrid.** Rule-based for structured tokens (cheap, deterministic); LLM-based opt-in for prose claims (Haiku 4.5; $0.05 per 6-run batch).
4. ~~Bundle YARA rules?~~ **Deferred** — no YARA function shipped yet.
