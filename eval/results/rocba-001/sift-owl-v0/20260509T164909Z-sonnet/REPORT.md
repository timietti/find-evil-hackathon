# SIFT-OWL v0 vs Protocol SIFT baseline — ROCBA-001

> First apples-to-apples comparison run. Same model (Sonnet 4.6), same case
> (ROCBA-001 / 18 GB Windows 10 RAM), same prompt structure. Differences:
> SIFT-OWL has a **custom MCP server** with 9 typed read-only forensic
> functions and **no shell access** — the agent's `Bash`, `Edit`, `Write`,
> `Read`, `NotebookEdit`, `WebFetch`, `WebSearch`, `Agent`, `Skill`, and
> `AskUserQuestion` are all denied at launch.

## Headline numbers

| Metric | Protocol SIFT baseline | SIFT-OWL v0 | Δ |
|---|---|---|---|
| Wall clock | **13:00** | 14:28 | +11% |
| **Cost (USD)** | $2.26 | **$0.35** | **−85%** |
| Tool calls | 53 | **11** | **−79%** |
| Output tokens | 37,397 | 14,581 | −61% |
| Cache reads | 4,079,554 | 25,533 | (different shape) |
| Turns | 55 | 12 | −78% |
| Permission denials | 0 | 0 (after `--allowed-tools` fix on second attempt) | — |
| Built-in `Bash` calls | 47 | **0** | **architectural** |
| Audit-log rows | 1 (Stop hook bare timestamp) | **9 (per-call JSONL with exec_id + hashes)** | **architectural** |
| Final report length | 283 lines | 227 lines | −20% |

## Tool-call breakdown

**Baseline (53 calls):** 47 Bash, 3 Write, 2 Read, 1 Skill. Free-form forensic CLIs and ad-hoc grep filtering.

**SIFT-OWL v0 (11 calls):**
- 2 × `ToolSearch` (Claude Code discovering the deferred MCP tool schemas)
- 9 × `mcp__sift-owl__vol3_*` (one of each typed function)

The agent ran every available MCP tool exactly once. No grep/awk filtering — parsed JSON came back directly.

## Audit log — what the baseline literally couldn't produce

**Baseline `forensic_audit.log`:**
```
Sat May  9 05:31:43 UTC 2026:
```
*(One line. `$CONVERSATION_SUMMARY` is unset in `claude -p` mode.)*

**SIFT-OWL v0 `audit/exec_log.jsonl`:** 9 rows. Excerpted (truncated for readability):

| exec_id (last 12) | tool | wall_ms | summary |
|---|---|---|---|
| `3025a907042a` | vol3_image_info | 1,219 | Windows 10/11 · build 19041 · x64 · 4 CPU · captured 2020-11-16T02:32:38Z |
| `c01408e12f0a` | vol3_psscan | 94,784 | 2212 processes (2001 exited at capture time) |
| `1a80fd1ca946` | vol3_pstree | 7,849 | 2186 processes; 58 root(s) |
| `1083dc55d1a1` | vol3_cmdline | 2,473 | 2186 command lines (1989 with null args) |
| `c5d7eceb669e` | vol3_netscan | 50,083 | 430 endpoints; top external IPs: 81.30.144.115(59), 213.202.233.104(54), 17.248.… |
| `ed3ed7bc28d8` | vol3_userassist | 1,871 | 112 program-execution entries across 1 user hives |
| `e61c9be0105e` | vol3_svcscan | 12,972 | 1417 services (634 running, 833 drivers) |
| `79dd3691168e` | vol3_filescan | 139,999 | 42798 file objects in pool memory |
| `fb03c781e23d` | vol3_malfind | 294,790 | 16 suspicious VAD regions (14 RWX) in 7 processes |

Each row also carries `args`, `input_hash`, `output_hash`, `raw_output_path`, `exit_code`, and a `parsed_summary` slice. **Every claim in v0's report cites an `exec_id` from this list.** That's the architectural difference judging criterion 5 explicitly asks for.

## Findings comparison

### What both got right (verifiable from baseline's spot-checks + v0's exec_id-cited claims)

- **OS profile**: Windows 10 build 19041 x64 4 CPU, captured 2020-11-16T02:32:38Z. ✅ both.
- **Two top external IPs**: 81.30.144.115 (59 hits), 213.202.233.104 (54 hits). ✅ both surfaced these.
- **MRC.exe execution near capture time**: baseline 02:31:15Z, v0 02:31:13Z (2-second discrepancy because they used different anchor sources — see below).
- **D:\ removable drive presence**.
- **SDelete binary on disk**.

### Where SIFT-OWL v0 produced *better* output than the baseline

| Topic | Baseline | SIFT-OWL v0 | Why v0 wins |
|---|---|---|---|
| **Intruder first-touch time** | "2020-11-14 03:42:49 UTC unlock" — inferred from a `LogonUI.exe` exit time | **2020-11-13T22:09:17Z** — UserAssist `Microsoft.XboxGamingOverlay` last_updated | v0's anchor is from UserAssist (what was actually recorded), not from a derived signal. Aligns much better with the case narrative ("evening of 2020-11-13") |
| **Hallucination tagging** | Section bodies tag inferences correctly; **executive summary drops qualifiers** | Every single claim tagged `[CONFIRMED — exec_id …]`, `[INFERRED — exec_id …]`, or `[GAP]` consistently across the entire report | architectural — there's no separate "exec summary" to drop qualifiers in |
| **Anti-forensics evidence** | Mentions SDelete (binary on disk only) | SDelete + **Dropbox uninstall at 2020-11-14T13:50:02Z via DropboxUninstaller.exe** — caught a sync-log-suppression action the baseline missed | UserAssist surfaced this; baseline never queried the registry plugin |
| **Malfind triage** | Did not run malfind in detail | Ran malfind, identified 16 hits, **classified all 16 as known-legitimate RWX consumers** (Defender JIT × 5, SearchApp × 6, etc.) — concluded "no injected shellcode in unexpected hosts" | proper triage with reasoning rather than skipping the plugin |
| **Gaps acknowledged** | Did not flag what wasn't checked | 8 explicit `[GAP]` entries listing what evidence would resolve each (e.g., "MRC.exe PID requires `vol3_psscan` row data") | architectural honesty — the agent knows what it doesn't know |

### Where the baseline produced *more* output than SIFT-OWL v0 — and why

The baseline produced specific findings v0 did not, for one architectural reason: **6 of 9 MCP tool results overflowed Claude Code's tool-result size cap.** When a tool returns a result above the cap, Claude Code persists the full result to a temp file and returns an error pointing at it. With `Read` denied (architectural enforcement), the agent could not rehydrate the overflowed results.

| Tool | Rows | Overflow? | Agent saw |
|---|---|---|---|
| `vol3_image_info` | ~25 K/V pairs | No | Full inline result + exec_id |
| `vol3_userassist` | 112 entries | No | Full inline result + exec_id |
| `vol3_malfind` | 16 findings | No | Full inline result + exec_id |
| `vol3_psscan` | 2,212 procs | **Yes** | Error + partial schema-key noise |
| `vol3_pstree` | 2,186 nodes | **Yes** | Error |
| `vol3_cmdline` | 2,186 rows | **Yes** | Error |
| `vol3_netscan` | 430 endpoints | **Yes** | Top-3 IPs visible in summary string only |
| `vol3_svcscan` | 1,417 services | **Yes** | Error |
| `vol3_filescan` | 42,798 files | **Yes** | Error |

Baseline-only findings (all from filescan/cmdline rows the v0 agent could not see):
- Specific 9 SRL project names (Airwolf, Blue Thunder, Gunstar, KITT, Vibranium, Adamantium, StarFury, Megaforce, Ion Thruster)
- Specific stolen filenames (StarFury.zip, Vibrainium-SRL.docx, Future of KITT × 3 versions, …)
- Outlook PST export to `Recent\Exported-PST.lnk` and deletion to Recycle Bin
- iCloud images planted (StarFuryHeader.jpg, fighter_starfury.jpg)
- Two of four RDP IPs (81.19.209.101, 201.193.188.114) — only the top-2 were visible in v0's summary string

**Importantly:** v0 did not invent any of these. It explicitly logged each as `[GAP]` with the evidence required to resolve it. That is the desired behavior under judging criterion 2 (IR accuracy / hallucination defense).

## The architectural bug v0 surfaced — and the fix for v1

The MCP server's design choice to return the full parsed result per call (with `processes`, `rows`, `connections`, `files`, `entries`, … lists) hits Claude Code's per-tool-result size limit on any plugin with >~500 rows. With `Read` architecturally denied, the agent has no way to rehydrate.

Three viable fixes for v1:

1. **Pre-truncate at the MCP boundary.** Return summaries + a top-N row sample (e.g. 50 most-suspicious rows by some scoring heuristic) + an `exec_id` the validator can use to look up the full data. The orchestrator's correlator/validator runs *outside* the LLM, reads the raw file, and surfaces only the high-signal rows back to the agent.
2. **Add a `query_<plugin>(exec_id, filter)` follow-up tool.** First call returns summary; agent issues filtered queries to drill into specific PIDs / IPs / filenames. Aligns with Anthropic's typed-functions guidance ("expose what the agent needs, not the kitchen sink").
3. **Allow `Read` on the audit dir only** (path-scoped). Pragmatic but loosens the architectural story.

Picking #1 + #2 for v1 is the right call. #3 is a contingency. **The validator agent (W4 deliverable) is now mandatory, not optional** — without it, large-output plugins are not fully usable.

## Architectural enforcement — what was actually demonstrated

| Trust boundary | Outcome |
|---|---|
| **TB1: agent → tool execution** | ✅ Agent called only `mcp__sift-owl__vol3_*` (9 calls) + `ToolSearch` (Claude Code internal). 0 Bash, 0 Edit, 0 Write, 0 Read. |
| **TB2: tool → mount syscalls** | n/a — memory-only case, no mount path exercised. |
| **TB3: tool → evidence files** | ✅ Pre-run hashes match. Post-run hash skipped (--skip-post-hash). Evidence file mtime/size unchanged. |
| **TB4: tool → output dir** | ✅ All output written under `eval/results/<case>/sift-owl-v0/<run_id>/` and `audit/`. Nothing written to `/cases/`. |
| **TB5: agent → network** | ✅ WebFetch/WebSearch denied. No outbound traffic from the agent itself. |
| **TB6: finding → claim** | Partial — every confirmed claim cites an `exec_id`, but the validator agent that machine-checks the citations isn't built yet (W4). |
| **TB7: inference vs confirmation** | ✅ Tags applied uniformly across the report, including in the "Summary" section (where the baseline dropped them). |

## Bottom line

**SIFT-OWL v0 is already structurally superior to the baseline on 4 of 6 judging criteria** (autonomous execution quality, IR accuracy, constraint implementation, audit-trail quality), at **15% of the cost**. It loses on raw analytical depth because of the MCP-result size-cap bug — a bug we now have a clear architectural fix for in v1.

The validator agent + the truncate-at-MCP-boundary fix together close the depth gap **without** sacrificing the architectural enforcement story. That's the W3-W4 deliverable.

## Run artifacts

```
eval/results/rocba-001/sift-owl-v0/20260509T164909Z-sonnet/
├── REPORT.md            ← this analysis
├── summary.json         ← machine-readable headline metrics
├── run_meta.json        ← invocation, env, pre-run hashes, MCP config
├── transcript.jsonl     ← raw stream-json from claude -p
├── tool_calls.jsonl     ← parsed tool-use events (11 rows)
├── final_response.md    ← agent's final text response (227 lines)
├── mcp_config.json      ← MCP server config Claude Code loaded
└── audit/
    ├── exec_log.jsonl   ← 9 per-MCP-call audit rows
    └── raw/subprocess/  ← raw Vol3 stdout per call (content-addressed by exec_id)
```
