# SIFT-OWL — Architecture

**Status:** v0.1 (2026-05-08). Living document — revise as the implementation forces decisions.

## Goals

1. **Architecturally enforce evidence integrity.** The agent must be unable to modify evidence even if the model misbehaves.
2. **Audit every finding back to a tool execution.** Every claim in the final report cites an `exec_id`.
3. **Beat Protocol SIFT's accuracy and hallucination rate** on the same case data.
4. **Self-correct without human intervention** within a hard iteration cap.
5. **Stay reproducible** — another practitioner can clone, install, point at a case, and get the same kind of report.

## System diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                       SIFT-OWL Orchestrator                              │
│  Claude Opus 4.7 · LangGraph state machine · plans, sequences,           │
│  evaluates, decides termination                                          │
└────────────┬───────────────────────────────────────────────┬─────────────┘
             │ A2A messages (logged: ts, from, to, tokens)   │
   ┌─────────┴───────┬────────────────┬────────────────┬─────┴────────┐
   │ Memory Agent    │ Disk Agent     │ Timeline Agent │ Win-Arts Agent│
   │ Sonnet 4.6      │ Sonnet 4.6     │ Sonnet 4.6     │ Sonnet 4.6    │
   │ (Vol3 +         │ (TSK + EWF     │ (Plaso super-  │ (EZ Tools +   │
   │  Baseliner)     │  + carving)    │  timeline)     │  EVTX/Reg)    │
   └─────────┬───────┴───────┬────────┴───────┬────────┴────────┬─────┘
             │               │                │                 │
             └───────────────┴───────┬────────┴─────────────────┘
                                     │
                  ┌──────────────────┴──────────────────┐
                  │    SIFT-MCP server (stdio MCP)      │
                  │  Typed read-only functions only.    │
                  │  No shell, no network, no writes    │
                  │  outside ./analysis|exports|reports.│
                  │  Per-call exec_log.jsonl row.       │
                  └──────────────────┬──────────────────┘
                                     │  subprocess (caps dropped)
                                     ▼
   ┌────────────────────────────────────────────────────────────────┐
   │  SIFT tools  ·  Vol3, TSK, EZ Tools, Plaso, YARA, bulk_extr.   │
   └─────────────────────────┬──────────────────────────────────────┘
                             │  ro,noatime,noexec mount
                             ▼
   ┌────────────────────────────────────────────────────────────────┐
   │ Evidence:  /cases/<CASE>/    ← chattr +i set on session start  │
   │ Outputs:   ./analysis/  ./exports/  ./reports/                 │
   │ Audit:     ./audit/{exec_log,agent_msgs,iter_N,evidence_hashes}│
   └────────────────────────────────────────────────────────────────┘

After each iteration, two non-LLM passes run before the report is emitted:
  ┌────────────────────────────┐    ┌────────────────────────────────┐
  │ Cross-source correlator    │ ─► │ Hallucination validator        │
  │ disk ↔ memory ↔ EVTX       │    │ every "confirmed" claim must   │
  │ flag mismatches            │    │ cite an exec_id whose parsed   │
  │                            │    │ output structurally supports it│
  └────────────────────────────┘    └────────────────────────────────┘
```

## Trust boundaries

| # | Boundary | Enforcement | Type | Test |
|---|---|---|---|---|
| TB1 | Agents → tool execution | MCP function whitelist; no `Bash` exposed to any agent | **Architectural** | `tests/test_no_shell_exposed.py` — assert `Bash` is not in any agent's tool list |
| TB2 | MCP server → mount syscalls | All `mount` calls hardcode `ro,noatime,noexec`; rw-mount path is unreachable | **Architectural** | `tests/test_mount_flags.py` — fuzz inputs, assert flags |
| TB3 | Tool subprocess → evidence files | `chattr +i` on every E01/img file at session start; subprocess `setrlimit` + dropped caps | **Architectural** | `tests/test_spoliation.py` — full agent run, then `find /cases -newer <session-start>` must be empty |
| TB4 | Tool subprocess → output dir | Subprocess CWD pinned to `<case>/analysis/`; absolute paths starting with `/cases/`, `/mnt/`, `/media/` rejected at MCP boundary | **Architectural** | `tests/test_output_paths.py` |
| TB5 | Agents → network | MCP server exposes no HTTP/curl/wget; subprocess `unshare -n` for tool invocations that don't need network (everything except Vol3 first-run symbol fetch) | **Architectural** | `tests/test_no_network_egress.py` — run with iptables drop-all, must still complete cached cases |
| TB6 | Finding → claim | Validator agent checks every "confirmed" claim cites an `exec_id` whose parsed output structurally supports the claim; demote to "inference" otherwise | **Hybrid** (prompt + validator) | `tests/test_validator.py` with synthetic claim/evidence pairs |
| TB7 | Inference vs. confirmation | Agents instructed to tag every claim `confirmed` / `inferred` / `hypothesis`; validator cross-checks confirmed claims | **Prompt + post-hoc** | Documented failure mode in `ACCURACY_REPORT.md` |

TB6 and TB7 are the only hybrid boundaries. The accuracy report explicitly documents what happens when the model ignores them — judging criterion 4 requires this.

## MCP server function inventory (W2 target)

Every function returns:
```jsonc
{
  "exec_id": "01H...ULID",
  "tool": "vol3_pslist",
  "args": { "image": "...", "..." },
  "exit_code": 0,
  "started_ts": "2026-05-08T19:22:01Z",
  "finished_ts": "2026-05-08T19:22:09Z",
  "input_hash": "sha256:...",        // hash of input args + evidence hashes
  "output_hash": "sha256:...",       // hash of raw tool output
  "raw_output_path": "./analysis/raw/01H....txt",
  "parsed": { /* structured JSON parsed from raw output */ },
  "summary": "1 hidden process; 12 unsigned services"   // short LLM-suitable string
}
```

The agent only ever sees `exec_id` + `summary` + a slice of `parsed`. Raw output stays on disk.

### Memory (wraps Vol3 + Memory Baseliner)

| Function | Wraps | Returns |
|---|---|---|
| `vol3_image_info(image)` | `windows.info` | OS build, profile, capture timestamp |
| `vol3_pslist(image)` | `windows.pslist` | Linked-list processes |
| `vol3_psscan(image)` | `windows.psscan` | Pool-scanned processes (incl. hidden/exited) |
| `vol3_pstree(image)` | `windows.pstree` | Parent/child tree |
| `vol3_cmdline(image, pid?)` | `windows.cmdline` | Command lines |
| `vol3_netscan(image)` | `windows.netscan` | Network connections |
| `vol3_malfind(image, pid?)` | `windows.malfind` | RWX/PE-headed VAD regions |
| `vol3_svcscan(image)` | `windows.svcscan` | Services |
| `vol3_handles(image, pid)` | `windows.handles --pid` | Open handles |
| `vol3_modules(image)` + `vol3_modscan(image)` | both kernel module enumerators | Combined diff returned |
| `baseliner_proc_diff(image, baseline)` | `baseline.py -proc --loadbaseline` | Non-baseline processes |

### Disk (wraps Sleuth Kit + EWF)

| Function | Wraps |
|---|---|
| `ewf_verify(e01)` | `ewfverify` |
| `ewf_info(e01)` | `ewfinfo` |
| `mount_e01_ro(e01)` | `ewfmount` + loop mount with hardcoded `ro,noatime,noexec` |
| `unmount(mountpoint)` | `umount` |
| `tsk_partition_table(raw)` | `mmls` |
| `tsk_fs_stat(raw, offset)` | `fsstat` |
| `tsk_fls_recursive(raw, offset)` | `fls -r -p` |
| `tsk_bodyfile(raw, offset)` | `fls -r -m /` |
| `tsk_icat(raw, offset, inode, dest)` | `icat` to `./exports/` |
| `tsk_recover(raw, offset, dest)` | `tsk_recover` |
| `mactime_timeline(bodyfile)` | `mactime -y -z UTC` |

### Windows artifacts (wraps EZ Tools)

| Function | Wraps |
|---|---|
| `extract_mft(image_or_mount)` | `MFTECmd` → CSV |
| `parse_evtx(logs_dir)` | `EvtxECmd --maps` → CSV |
| `parse_registry(config_dir)` | `RECmd --bn <plugin>` → CSV |
| `extract_amcache(amcache_hve)` | `AmcacheParser` |
| `extract_shimcache(system_hive)` | `AppCompatCacheParser` |
| `extract_prefetch(prefetch_dir)` | `PECmd` |
| `extract_srum(srudb_dat)` | `SrumECmd` |

### Threat hunting

| Function | Wraps |
|---|---|
| `yara_scan(target_path, rules)` | `yara -r` |
| `bulk_extractor_carve(image, dest)` | `bulk_extractor -j 4` |
| `vol3_vadyarascan(image, rules, pid?)` | `windows.vadyarascan` |

### Timeline

| Function | Wraps |
|---|---|
| `plaso_extract(source, dest)` | `log2timeline.py` |
| `plaso_filter(plaso_db, time_range, filters)` | `psort.py` |
| `plaso_info(plaso_db)` | `pinfo.py` |

**Total: ~35 typed functions.** Wide enough for depth, narrow enough that we can build, test, and harden every one in 5 weeks.

## Audit log schemas

### `audit/exec_log.jsonl` — one row per MCP function call

```jsonc
{ "exec_id":"01H...", "ts":"2026-05-08T19:22:01Z", "agent":"memory_agent",
  "tool":"vol3_psscan", "args":{"image":"/cases/.../mem.img"},
  "input_hash":"sha256:...", "output_hash":"sha256:...",
  "raw_output_path":"./analysis/raw/01H....txt", "exit_code":0,
  "wall_ms":7820, "summary":"42 procs; 1 hidden (PID 1912)" }
```

### `audit/agent_msgs.jsonl` — one row per inter-agent message

```jsonc
{ "ts":"2026-05-08T19:22:09Z", "from":"orchestrator", "to":"memory_agent",
  "type":"task", "iteration":1, "content_hash":"sha256:...",
  "tokens_in":1234, "tokens_out":0, "model":"claude-opus-4-7" }
```

### `audit/iteration_N.json` — per-iteration plan + outcome

```jsonc
{ "iteration":1, "plan":["psscan","pstree","malfind","cmdline"],
  "exec_ids":["01H...","01H..."], "findings":[...],
  "validator_demotions":[ {"claim":"...", "reason":"..."} ],
  "next_plan_diff":["+amcache lookup for STUN.exe MFT entry"] }
```

### `audit/evidence_hashes.json` — recorded at session start, re-checked at end

```jsonc
{ "session_start_ts":"...", "files":[
  { "path":"/cases/.../disk.E01", "size":..., "sha256":"...", "mtime":"..." },
  ...
] }
```

## Self-correction loop

```
plan → execute (specialists) → correlate → validate → score
   ↑                                                    │
   └── if score < threshold AND iter < cap, replan ─────┘
```

**Termination conditions** (any one fires):
- `iteration >= 3`
- wall-clock ≥ `--wall-clock-min` (default 15)
- total tokens ≥ `--max-tokens` (default 1.5M)
- validator demotion rate < 5% AND no new findings in this iteration (converged)

**Replan signal** — the orchestrator reads `iteration_N.json` and is prompted to:
1. List demoted claims and what evidence would be needed to confirm.
2. List specialist tasks that returned no findings — were they the wrong tool, or genuinely empty?
3. List cross-source mismatches surfaced by the correlator.
4. Emit a new plan as a JSON list of `{specialist, task, expected_evidence}`.

## Cross-source correlator

A non-LLM pass between specialists and validator. For a known set of correlation rules, e.g.:

- For every suspicious process from memory: look up its image path in MFT, AmCache, ShimCache, Prefetch.
- For every "first execution" timestamp: compare across AmCache, Prefetch, EVTX 4688, NTFS `$STANDARD_INFORMATION`.
- For every external IP from `netscan`: scan disk strings + browser history + DNS cache.
- For every service in `svcscan`: cross-check against registry `Services` key from disk.

Mismatches are surfaced as `correlator_findings` with severity. The orchestrator gets the summary; the validator demotes any "confirmed" claim that the correlator contradicts.

## Hallucination validator

Per "confirmed" claim, the validator:

1. Parses the claim for testable assertions (PID, file path, IP, timestamp, hash).
2. Looks up the cited `exec_id`'s `parsed` structure.
3. Verifies the assertion is structurally present (regex / JSONPath).
4. If not present → demote to `inferred` and log reason.
5. If the validator itself isn't sure → demote conservatively + flag for human review.

The validator is itself a small Claude call with no tool access — it sees only the claim text and the parsed JSON for the cited `exec_id`. It cannot run tools or hallucinate new evidence.

## Termination & safety

- Hard caps on iterations, wall-clock, tokens, sub-agent recursion depth.
- The orchestrator can request `STOP` early if confidence is high enough (validator demotion rate < 5%, no cross-source mismatches).
- Every cap hit logs the partial state to `audit/` and emits the best-so-far report.

## Open questions (resolve before W3)

1. Does LangGraph's checkpointer give us free iteration replay for free? (If yes, simplify our state machine.)
2. Should specialist agents call MCP server directly, or only via the orchestrator? (Direct is faster + better isolation; via-orchestrator is easier to audit. Lean direct.)
3. Validator: rule-based, LLM-based, or hybrid? (Lean hybrid: rule-based for structured claims, LLM-based for prose claims, fail-closed.)
4. Do we ship a default YARA ruleset or require the user to bring one? (Bundle a curated minimal set + document how to add.)
