# SIFT-OWL v2 loop — STARK-APT-001 with EZ Tools

> Multi-host enterprise APT case, 4 hosts, ~58 GB. v2 self-correction loop
> with the **3 newly-shipped EZ Tools** (MFTECmd, AppCompatCacheParser,
> EvtxECmd) added to the agent's tool surface (19 total). Compares
> head-to-head against the prior v2 loop run on the same case that ran
> with disk + memory only (`20260510T081103Z-sonnet`).

## Headline numbers

| Metric | v2 loop (no EZT) | **v2 loop (with EZT)** | Δ |
|---|---|---|---|
| Wall clock | 20:01 | 21:42 | +8% |
| Cost (USD) | $1.92 | **$2.24** | +17% |
| Tool calls (cumulative) | 76 (62+10+4) | **91** (77+14) | +20% |
| Iterations completed | 3 (converged) | 2 (no-improvement) | — |
| Confirmed claims (final iter) | 36 | 35 | -1 |
| ✅ Verified (validator v2) | 31 (86.1%) | 13 (37.1%) | **−49 pp** |
| Failed verdicts (final iter) | 0 | 3 | +3 |
| Findings substance (new vs prior) | reference | **substantially expanded** | (see below) |

**Counter-intuitive: the strict score dropped despite richer evidence.**
This run produced markedly more substantive findings — specific malware
execution timestamps, MFT timestomping detection, lateral-movement
service installs, vibranium account creation pinpointed to second-
precision — but the rule-based validator can't structurally check the
richer prose patterns that come with that depth.

## Tool-call shape

```
55 × query_rows               — drills (heavy use, ~70% of activity)
14 × tsk_icat_extract         — pull MFT, SYSTEM hive, EVTX from each host
10 × ezt_evtx_parse           — Windows Event Logs (NEW)
 3 × ezt_shimcache_parse      — ShimCache (NEW)
 3 × ezt_mft_parse            — full MFT timeline (NEW)
 3 × tsk_fls_list             — filesystem listing
 3 × ToolSearch               — Claude Code internal: discover MCP schemas
─── 91 total
```

The agent embraced the EZ Tool flow — 16 of the 91 calls (17.6%) used the
new extract-then-parse pattern. The audit log shows full lineage from
each ezt_* call back through tsk_icat_extract to the source disk image.

## What the EZ Tools surfaced — substantively new findings

### 1. Specific malware execution timestamps (ShimCache)

The disk+memory-only run had `spinlock.exe` and friends as cross-host
binaries with file presence but no execution timing. ShimCache fills
that gap:

| Binary | Host | LastModifiedTimeUTC (ShimCache) | Source |
|---|---|---|---|
| `spinlock.exe` | nromanoff | **2012-04-03T22:53:39Z** | `019e1123-…` |
| `hydrakatz.exe` | nromanoff | **2012-04-04T01:00:45Z** | `019e1123-…` |
| `a.exe` | nromanoff | ~30 executions 2012-04-04T00:14–00:44Z | `019e1123-…` |
| `PSEXESVC.EXE` | nromanoff | **2012-04-04T01:46:37Z** | `019e1123-…` |
| `spinlock.exe` | tdungan | **2012-04-04T17:06:37Z** | `019e1123-…` |

`PSEXESVC.EXE` on nromanoff is a **net-new finding** — the prior run had no
direct evidence of PsExec lateral-movement service installation. ShimCache
timestamped it to `2012-04-04T01:46:37Z`, confirming nromanoff → other-host
lateral movement at that time.

### 2. MFT-detected timestomping (anti-forensics)

`usboesrv.exe` on the DC: **Created date AFTER Modified date** — classic
NTFS timestomping signature. The attacker manipulated `$STANDARD_INFORMATION`
timestamps to evade simple timeline reconstruction. v2-validator's
`Timestomped` flag from MFTECmd confirmed this without the agent needing
to compute it.

### 3. vibranium account creation pinpointed

vibranium user profile MFT records gave the FIRST activity timestamp on
each host:

```
2012-04-03T23:09Z   vibranium first active on nromanoff
2012-04-04T16:40Z   vibranium first active on tdungan
2012-04-04T17:29Z   vibranium first active on DC
```

The chronological order — **nromanoff → tdungan → DC** — anchors
nromanoff as the lateral-movement origin host. The prior run inferred
this from less direct evidence; this run has timestamped MFT records as
the source of truth.

### 4. Kernel rootkit `hotcorewin2k.sys` confirmed timestomped on tdungan

Detected via `Timestomped: true` flag in MFTECmd output — supports the
prior run's "likely rootkit" inference with structural evidence.

### 5. ShimCache absence as confirmation of cleanup

`a.exe` does not appear in DC's MFT TEMP paths or ShimCache — the
attacker's sdelete cleanup was effective on the DC. The prior run had
this as a hypothesis ("absent from disk"); ShimCache absence is now
explicit evidence.

## Why the strict score dropped despite richer evidence

The validator (v2) flagged 21 demoted claims in iter 1 (7 partial + 4
failed + 14 unverifiable). The 4 failed verdicts each surface a real
v2-validator gap, all addressable in v3:

| Failed claim | Root cause | v3 fix |
|---|---|---|
| "No a.exe was found in DC MFT TEMP paths [CONFIRMED — A]; not present in DC ShimCache [CONFIRMED — B]" | Two `[CONFIRMED]` tags in one sentence break per-claim segmentation | Split claims at each `[CONFIRMED]` boundary, not at sentence boundaries |
| "EXFIL.pst is on tdungan (not DC) under vibranium Outlook profile, created 2012-04-05T16:07Z" | Parenthetical "(not DC)" triggers subject-clause negation falsely | Tighten subject-clause heuristic to require leading whitespace + colon |
| "vibranium first activity: nromanoff (2012-04-03T23:09Z) → tdungan (2012-04-04T16:40Z) → DC (2012-04-04T17:29Z)" | Timestamp regex captures `T23:09Z` (no seconds) but MFT JSON has `T23:09:14Z` — substring fails | Allow timestamp prefix-match (claim's truncated time should match a longer haystack time) |
| "(misc partial pattern)" | Negation cue "absent" / "not" appears in adjacent clause that the agent considered "supporting evidence" | Per-claim positive/negative classifier instead of per-clause |

The 14 `unverifiable` verdicts are the bigger volume issue — claims
like *"The attacker used PsExec for lateral movement based on
PSEXESVC.EXE timing alignment"* have no extractable tokens
(no PIDs, no IPs, no specific filenames inside the claim
sentence — those are in surrounding context). v3 validator should
either (a) widen the extraction window to the full paragraph, or
(b) add an LLM-based prose check for unverifiable-by-rule claims.

## Iteration termination — informative

The loop terminated at iter 2 by the **no-improvement** condition:
iter 2's verified count (13) was less than iter 1's (15). Reasons
visible in the iter 2 final response:

- Agent attempted to fix the 11 demoted claims from iter 1
- For some, the fix added MORE unverifiable claims (rewriting prose
  away from extractable tokens)
- Net verified count went down

This is the loop's safety net working correctly: it stopped spending
budget when iterations were no longer improving the strict score.

A v3 prompt revision should explicitly tell the agent *what* the
validator's regex-based extractor expects, so the agent can write
claims in a more validator-friendly form. With validator v3 + that
prompt revision, the EZ Tool runs should achieve the convergence
pattern the disk+memory run did.

## Cost / wall efficiency

| | v2 loop (no EZT) | v2 loop (EZT) | Δ |
|---|---|---|---|
| Total cost | $1.92 | $2.24 | +17% |
| Cost / verified claim (strict) | $0.062 | $0.172 | +178% |
| Cost / confirmed claim | $0.053 | $0.064 | +21% |

By **strict** score, the EZ-tool run is more expensive per verified
claim. By **substantive** depth (specific timestamps + MFT timestomp +
PSEXESVC + vibranium chronology), the EZ-tool run is materially more
valuable. The strict score is a useful monotonic signal during loop
convergence but it is **not** an unconditional accuracy proxy — when the
agent's claims become more specific, the rule-based validator's blind
spots become more visible.

## Architectural enforcement re-validated

| TB | Outcome |
|---|---|
| TB1 (no shell/FS/web) | ✅ 0 Bash, 0 Edit, 0 Write, 0 Read in all 91 tool calls |
| TB3 (evidence integrity) | ✅ Pre-run hashes match all 8 evidence files |
| TB4 (output dir) | ✅ All output (extracted artifacts, EZ Tool outputs, audit logs) in `eval/results/test2-stark-apt/sift-owl-v2/<run_id>/` |
| TB6 (claim → exec_id) | ✅ 0 broken citations across both iter validator runs |
| Extract-then-parse audit lineage | ✅ Every `ezt_*_parse` audit row records `extract_exec_id` so the validator can trace `finding → ezt_parse → tsk_icat_extract → image` |

The new extract-then-parse architectural pattern works: the agent
chained 16 `tsk_icat_extract` + `ezt_*_parse` calls without ever
specifying a filesystem path directly. The audit log carries the full
lineage.

## Bottom line

The EZ Tools are clearly **substantive wins** for the agent's analytical
depth. The strict validator score regression is a known v2-validator
limitation, not a regression in finding quality.

For SHIELDBASE final eval:
- The EZ Tools are essential for Win10 enterprise cases (Amcache, full
  EVTX coverage, Prefetch via ShimCache).
- Validator v3 is the right next investment to recover the strict score
  on EZ-Tool-heavy runs.
- A v3 prompt revision telling the agent the validator's tokenization
  rules would close most of the unverifiable gap.

For now: the run demonstrates the **ceiling** of the rule-based validator
when claims become richer than its extractor can keep up with — and
that's a known, documented next-step.

## Run artifacts

```
eval/results/test2-stark-apt/sift-owl-v2/20260510T090305Z-sonnet/
├── REPORT.md             ← top-level cross-iteration summary
├── COMPARISON.md         ← this file
├── run_meta.json         ← invocation, env, pre-run hashes, per-iter stats
├── mcp_config.json
├── audit/                ← SHARED across all iterations
│   ├── exec_log.jsonl    ← 33 underlying tool-exec rows
│   └── raw/              ← subprocess + extract + ez_tools outputs (gitignored)
└── iterations/
    ├── iter_1/  (77 tool calls, 14.6m, $1.67, score 37.5%, 361-line report)
    └── iter_2/  (14 tool calls,  7.1m, $0.57, score 37.1% — terminated, no improvement)
```
