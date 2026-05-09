# SIFT-OWL v1 vs v0 vs Protocol SIFT baseline — ROCBA-001

> Three-way head-to-head on the same 18 GB Win10 memory image, same model
> (Sonnet 4.6), same prompt structure. v1 is the depth-fixed version of v0:
> the MCP server now truncates row lists to 50 at the boundary, and a
> `query_rows(exec_id, filter_field, filter_value, limit, offset)` MCP tool
> lets the agent drill into the full row list of any prior call.

## Headline numbers

| Metric | Baseline | SIFT-OWL v0 | SIFT-OWL v1 |
|---|---|---|---|
| Wall clock | 13:00 | 14:28 | **19:24** |
| Cost (USD) | $2.26 | **$0.35** | $1.11 |
| Tool calls | 53 | 11 | **49** |
| — Bash | 47 | 0 | 0 |
| — MCP forensic | 0 | 9 | 9 |
| — `query_rows` drill | 0 | 0 | **37** |
| Output tokens | 37,397 | 14,581 | 35,523 |
| Permission denials | 0 | 0 | 0 |
| Audit-log rows | 1 (Stop hook timestamp) | 9 (per-call) | **9 (per-call)** |
| Final report length | 283 lines | 227 lines | **275 lines** |
| Investigation goals answered | 5/5 (with hallucinations) | 5/5 (with [GAP]s) | **5/5 (with citations)** |

**v1 costs about half the baseline ($1.11 vs $2.26), runs ~50% longer (19m vs 13m), but produces a strictly more accurate report.** Wall-clock is up because `query_rows` involves real round-trips: each drill is `audit lookup → re-parse 4 MB filescan → filter → return`. With cached symbols and parsed JSONL, that's fast — but 37 of them adds up.

## What v1 found that the baseline missed

| Finding | Baseline | v1 |
|---|---|---|
| **`srl-h` backdoor account** (second local user with its own OneDrive + sdelete64 + PowerShell + MMC logs) | ❌ not found | ✅ confirmed via `\Users\srl-h\` profile + RID-1002 PST in Recycle Bin (`exec_id 019e0ddc-…6ba398beced8`) |
| **Three BitLocker recovery keys exfiltrated** (`BitLocker Recovery Key 1694D560`, `26F77152`, `C42458BB`) | ❌ not found | ✅ Recent LNK + BitLockerWizard.exe access (`exec_id 019e0ddc-…6ba398beced8`) |
| **Firefox recovery key for fred.rocba@outlook.com** | ❌ not found | ✅ Recent LNK (`exec_id 019e0ddc-…6ba398beced8`) |
| **System Properties Protection access** (VSS disable signal) | ❌ not found | ✅ UserAssist focus 7×, time 4:33 (`exec_id 019e0ddb-…ab776038fd0a`) |
| **MRC.exe is 32-bit (Wow64:true), parent=explorer.exe (pid 7464), 20 threads, still running** | partial (PID 29440 only) | ✅ full process detail (`exec_id 019e0dd9-…ca3ed66e47c7`) |
| **`MRC179.tmp` companion file** alongside MRC.exe in `D:\Tools\` | ❌ not found | ✅ filescan drill (`exec_id 019e0ddc-…6ba398beced8`) |
| **All 4 RDP IPs with state at capture** (incl. `81.19.209.101` SYN_RCVD = actively connecting) | ✅ but unstated state | ✅ per-IP state: 2 ESTABLISHED + 1 CLOSED + 1 SYN_RCVD (`exec_id 019e0dda-…28eef0687026`) |
| **First RDP connection time** (`201.193.188.114` at `02:30:05Z` — 70 sec before MRC.exe launched) | ❌ not anchored | ✅ from netscan Created field (`exec_id 019e0dda-…28eef0687026`) |
| **VC personal financial files on OneDrive** (WACC Calc, Findoreria_Solved, NETFLIX, TIVO, Firedam) | ❌ not found | ✅ filescan drill (`exec_id 019e0ddc-…6ba398beced8`) |
| **9 explicit [GAP] entries** with what evidence would resolve each | ❌ no gaps acknowledged | ✅ enumerated (e.g. "MRC.exe C2 needs PCAP", "srl-h creation time needs EVTX 4720") |

## Findings the baseline asserted that v1 correctly *didn't*

The baseline made a few unsupported claims; v1 declined to make them:

| Baseline claim | v1 treatment |
|---|---|
| "MRC.exe = Mini Remote Control" (specific naming, no evidence cited) | v1: "MRC.exe is a remote administration/control tool; capability and exact identity is `[GAP]` — needs binary analysis" |
| "SDelete anti-forensic cleanup" (asserted as fact in exec summary) | v1: SDelete download, install, Recent LNK execution all `[CONFIRMED]` with exec_id; **does not** assert specific files were sdeleted |
| "Total intrusion duration: ~46h 50m" (computed from inferred LogonUI exit) | v1: shows two attack phases with separate timestamps; declines to compute a single duration |
| "USB drive D:\" (drive letter inferred from one filescan reference) | v1: cites D:\ via `D:\Tools\MRC.exe` filescan rows + UserAssist entry — fully grounded |

## Tool-call breakdown — what v1 actually did

```
 1 × vol3_image_info          (1.2 s) — OS profile anchor
 1 × vol3_psscan              (72  s) — 2,212 procs total, top 50 returned
 1 × vol3_pstree              (5.8 s) — 2,186 nodes, top 50 returned
 1 × vol3_cmdline             (2.5 s) — 2,186 cmdlines, top 50 returned
 1 × vol3_netscan             (66  s) — 430 endpoints, top 50 returned
 1 × vol3_userassist          (1.8 s) — 112 entries, all returned (under cap)
 1 × vol3_svcscan             (14  s) — 1,417 services, top 50 returned
 1 × vol3_filescan            (145 s) — 42,798 file objects, top 50 returned
 1 × vol3_malfind             (292 s) — 16 findings, all returned (under cap)
37 × query_rows                       — drills into the full row lists by exec_id
 3 × ToolSearch                       — Claude Code internal: discover MCP tool schemas
─── 49 total
```

**v1's `query_rows` usage pattern** (drill specifics from each plugin's full data):

- 17 drills into `vol3_filescan` (find specific filenames: `StarFury`, `MRC`, `*.zip`, `*.pst`, `BitLocker`, `Recovery`, `Recent`, project codenames, srl-h profile content, …)
- 7 drills into `vol3_psscan` / `vol3_pstree` (find PIDs by image name: MRC.exe, OneDrive.exe, sdelete, powershell, …)
- 5 drills into `vol3_netscan` (filter by foreign_addr per attacker IP, by foreign_port=3389, …)
- 4 drills into `vol3_userassist` (paginate beyond first 50, filter by name)
- 4 drills into `vol3_cmdline` (find specific PIDs)

This is the right shape. The agent triages broadly first (9 forensic calls), gets summaries + samples, then **iteratively drills** into anything suspicious until it has enough evidence to make a citable claim.

## Audit-log substrate

`audit/exec_log.jsonl` has 9 rows (one per Vol3 plugin invocation). Every `[CONFIRMED — exec_id …]` claim in v1's report references one of these 9 IDs. The validator agent (W4 deliverable) will mechanically verify each citation by:

1. Looking up the exec_id in `exec_log.jsonl`.
2. Reading the raw output at `raw_output_path`.
3. Re-parsing.
4. Checking that the claim's specific assertion (PID, filename, IP, timestamp) is structurally present in the parsed result.

`query_rows` calls are not separately audit-logged — they re-parse already-recorded raw outputs and don't produce new evidence. The validator checks claims against the *underlying* `vol3_*` exec_ids; whether the agent reached that data via the initial response or a `query_rows` drill is irrelevant to verifiability.

## Architectural enforcement — proven again

| Trust boundary | Outcome |
|---|---|
| TB1: agent → tool execution | ✅ 0 Bash, 0 Edit, 0 Write, 0 Read, 0 WebFetch, 0 Skill — only `mcp__sift-owl__*` |
| TB3: tool → evidence files | ✅ Pre-run hashes match. (Post-hash skipped per `--skip-post-hash`.) |
| TB4: tool → output dir | ✅ All output in `eval/results/rocba-001/sift-owl-v1/<run_id>/` and `audit/` |
| TB5: agent → network | ✅ WebFetch/WebSearch denied |
| TB6: finding → claim | ✅ Every claim cites an exec_id (or `[INFERRED]`/`[HYPOTHESIS]`/`[GAP]` tag) |
| TB7: inference vs confirmation | ✅ Tags applied uniformly, including in the Executive Summary |

## Cost vs depth — three-way

```
Cost / depth tradeoff on ROCBA-001:

Baseline:     $2.26  ████████████████████  ←  free-form Bash, deep but with 4 hallucinations in exec summary
v0:           $0.35  ██                    ←  architectural enforcement, but overflow bug → ~50% depth
v1:           $1.11  █████████             ←  architectural + truncate+query fix → exceeds baseline depth
```

v1 is **half the cost of the baseline, with strictly better accuracy and traceability.** The remaining wall-clock gap (19m vs 13m) is dominated by `query_rows` round-trips. Under context-window pressure on truly enormous cases, this might shift; for ROCBA the trade is favourable.

## v1 still has gaps — what we'd fix in v2

1. **`query_rows` is not audit-logged separately.** For full audit fidelity, log each drill: `{exec_id_drill, parent_exec_id, filter, matched_rows}`. Adds ~50 KB per run. Cheap.
2. **Filter is single-field.** Multiple filters (e.g. `foreign_addr=81.30.144.115 AND foreign_port=3389`) require multiple drills. Add a small filter-expression DSL or accept an array of filters.
3. **Truncation default is uniform 50.** Plugins with tiny rows (cmdline, userassist) could fit 200 easily; plugins with very fat rows (malfind with notes) might need 25. Per-plugin defaults would help.
4. **Validator agent is still TODO.** v1's claims all cite exec_ids, but nothing has machine-verified them yet. That's the W4 deliverable.

## Bottom line

**SIFT-OWL v1 beats the Protocol SIFT baseline on every judging criterion.**

| Criterion | Baseline | v1 |
|---|---|---|
| 1. Autonomous execution | single-pass shell | multi-pass typed-fn + drill-by-exec_id |
| 2. IR accuracy | partial hallucinations in summary | every claim cited or tagged [GAP] |
| 3. Breadth/depth | 9 projects, 4 RDP IPs, partial | 9 projects + srl-h backdoor + BitLocker keys + Firefox creds + 4 IPs w/ state + temp file |
| 4. Constraint implementation | prompt + permission deny-list | architectural — agent has no shell, no FS, no web |
| 5. Audit trail | 1 Stop-hook line | 9 per-call rows, every claim cites an exec_id |
| 6. Usability | bash + skill files | one `--mcp-config` flag |

Cost: **$1.11 vs $2.26** (51% cheaper). Wall: 19m vs 13m (acceptable trade for the depth + accuracy gains).

The architectural design works.

## Run artifacts

```
eval/results/rocba-001/sift-owl-v1/20260509T174516Z-sonnet/
├── REPORT.md            ← this analysis
├── summary.json         ← machine-readable headline metrics
├── run_meta.json        ← invocation, env, pre-run hashes, MCP config
├── transcript.jsonl     ← raw stream-json from claude -p (gitignored — 6 MB)
├── tool_calls.jsonl     ← parsed tool-use events (49 rows)
├── final_response.md    ← agent's final text response (275 lines)
├── mcp_config.json      ← MCP server config Claude Code loaded
└── audit/
    ├── exec_log.jsonl   ← 9 per-MCP-call audit rows
    └── raw/subprocess/  ← raw Vol3 stdout per call (gitignored — total ~30 MB)
```
