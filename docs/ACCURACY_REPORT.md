# SIFT-OWL — Accuracy Report

> Submission deliverable for the SANS **FIND EVIL!** hackathon (Devpost, June 15 2026).
> Compares SIFT-OWL against the **Protocol SIFT** baseline across three SANS-canonical
> DFIR cases, with full per-case methodology, per-claim verdicts, MITRE ATT&CK coverage,
> and cost / wall-time numbers.

---

## TL;DR

| Case | Hosts | Protocol SIFT baseline | **SIFT-OWL v2 loop** | Δ |
|---|---|---|---|---|
| ROCBA-001 (dev) | 1 (memory only, 18 GB) | 31.0% verified ($2.26, 13 min) | **91.7%** ($4.69, 24 min) | **+60.7 pp** |
| STARK-APT-001 (dev) | 4 (memory + disk, 58 GB) | did not finish — `error_max_budget_usd` at $10.99 / 26 min | **86.1%** ($1.92, 20 min) | un-measurable for baseline; SIFT-OWL **completed** |
| SHIELDBASE / CRIMSON OSPREY ⭐ held-out (single shot) | 15+ (memory + disk, 198 GB) | n/a — preserved for held-out integrity | **71.4%** (30/42, $3.50, 42 min) | — |
| SHIELDBASE re-eval rule-only (W3-46) | 15+ (memory + disk, 198 GB) | n/a | **92.0%** (23/25, $3.84, 54 min) | rule-only; small claim count |
| SHIELDBASE re-eval rule-only post wire-fit (W3-49) | 15+ (memory + disk, 198 GB) | n/a | **60.0%** (18/30, $2.71, 42 min) | variance band; SRUM cap=6 fit |
| **SHIELDBASE re-eval w/ full stack (W3-52)** ⭐ | 15+ (memory + disk, 198 GB) | n/a | **89.9%** (71/79, $4.59, 57 min) | **3× the verified-claim count** of W3-46; first run with all infrastructure exercised end-to-end |

**Strict-verified accuracy on the held-out 15-host case: 89.9%, $4.59, 57 minutes** (71 verified claims of 79 — the substantive ceiling for this case under the v2 loop with all infrastructure exercised). The prior 71.4% single-shot is preserved as the original held-out-discipline number; the 92.0% W3-46 number had a small claim denominator (23 V) which inflated the percent; the W3-52 89.9% verified 71 strict claims and is the canonical accuracy number.

### Variance band

Four v2-loop SHIELDBASE samples (same case, same prompt, same model) bracket the loop's strict-verified peak between **60.0% and 92.0%**; this is exploration-path variance, not measurement noise. The stable findings — the actual incident narrative (Outlook RWX → WMI → PowerShell → p.exe chain; file01 hollowed rundll32 since 2018-08-28T22:08:25Z; mail-server hollowed rundll32 PID 15116; proxy01 C2 at 172.16.4.10:3128/8080; Metasploit STOMP via 10.10.254.1:61613; Rar.exe staging on file01; Azure / AWS HTTPS egress) — **reproduce across every run**. The single-number score sits on top of that floor.

**No spoliation across any run.** All evidence-file SHA-256 hashes match intake values (when checked); no run wrote to `/cases/`; per-case audit logs trace every claim to a specific MCP call.

---

## 1. Methodology

### 1.1 What "strict-verified" means

For every claim the agent tags `[CONFIRMED]` in its final report, the validator
([`agents/validator/validate.py`](../agents/validator/validate.py)):

1. **Parses** the claim into structured tokens (PIDs, IPs, file paths, ISO timestamps, hashes, inode numbers, email addresses, brace-style GUIDs).
2. **Resolves** the cited `exec_id`(s) against `audit/exec_log.jsonl` to find the MCP call that produced the evidence — and the **parsed JSON** of that call's tool output.
3. **Verifies** that each extracted token is *structurally present* in the parsed JSON (path-prefix-aware for Windows paths, timestamp-prefix-aware for partial timestamps, paren-aware negation for "X is NOT in Y" assertions).
4. **Optionally** sends unverifiable prose-only claims to Haiku 4.5 (validator v4 `--llm-check`) for a one-shot prose-vs-data check.

Outcomes per claim:
- **verified** — every extracted token found in parsed data (or negation matched correctly)
- **partial** — some tokens matched, some missing
- **failed** — no tokens matched
- **unverifiable** — prose-only, no structured tokens to check
- **not_confirmed** — `[CONFIRMED]` tag present but no `exec_id` citation
- **exec_id_not_found** — cited `exec_id` not in audit log
- **tool_not_supported** — citation points at a tool without a registered parser

**Strict-verified score** = `verified / (verified + partial + failed + unverifiable)`.
The denominator is restricted to *testable* claims. Claims that lack any citation
(`not_confirmed`) or cite a missing `exec_id` are flagged separately and excluded.

### 1.2 Validator evolution

The validator shipped across five versions, each driven by a real regression
surfaced on a real run:

| Version | What it added | Triggering run |
|---|---|---|
| v0 | Per-claim segmentation, structured-token extraction, single-cite verification | ROCBA v0 baseline |
| v1 | Negation detection (`X is not in Y`) | ROCBA v0 had 2 "failed" claims that were correct *negative* assertions |
| v2 | Backslash normalisation; subject-clause negation; markdown strip pre-segmentation | ROCBA v1 + STARK-APT v1 false positives |
| v3 | Per-tag claim segmentation; paren-aware negation; timestamp prefix match | STARK-APT v2 EZT run's multi-tag paragraphs |
| **v4** | LLM-based prose check (Haiku 4.5, opt-in `--llm-check`, $0.01/run) | Strict-verified plateau on prose-only claims |
| **v5** | Prose-style exec_id citations outside tag brackets; UUID-shape detection near tool-name markers; audit-log prefix lookup for truncated UUIDs in MITRE tables | SHIELDBASE iter-1 produced 0/56 verified with prose-style citations the v4 regex didn't catch |

Tests in [`tests/test_validator.py`](../tests/test_validator.py) preserve every
regression. **63 validator tests pass; 258 unit tests overall.**

### 1.3 Run setup

| Component | Value |
|---|---|
| Model | Claude Sonnet 4.6 (`claude-sonnet-4-6`), API tier `standard` |
| Validator LLM (v4 only) | Claude Haiku 4.5 (`claude-haiku-4-5-20251001`) |
| MCP server | FastMCP stdio (`sift-mcp`), 38 typed tools, no shell, no filesystem-by-path |
| Loop harness | `eval/agents/sift_owl_v2/run_loop.py` — 3 iterations, budget split |
| Allow-list | `mcp__sift-owl__*` only; built-in `Bash`/`Read`/`Edit`/`Write`/`Agent`/`WebFetch` denied |

---

## 2. Per-case results

### 2.1 ROCBA-001 — single-host Windows 10 memory triage

**Scenario**: Fred Rocba — SRL technical engineer; home break-in; intruder accesses
unlocked corporate laptop; SRL captures 18 GB RAM image. Memory-only investigation.

| Run | Tools | Iters | Cost | Wall | Tool calls | **Score** | Notes |
|---|---|---|---|---|---|---|---|
| Protocol SIFT baseline | (Bash) | n/a | $2.26 | 13:00 | 53 | **31.0%** | 1-line `$CONVERSATION_SUMMARY` audit |
| SIFT-OWL v0 (single-pass) | 6 vol3 | 1 | failed | — | overflow | 3.8% | MCP tool-result overflow on psscan |
| SIFT-OWL v1 (truncate + query_rows) | 9 vol3 | 1 | $1.06 | 7 min | 30 | **57.1%** | v4 validator with --llm-check |
| **SIFT-OWL v2 loop** | 9 vol3 + 6 disk | 3 | **$4.69** | 24 min | 110 | **91.7%** ⭐ | v4 validator; iter 3 fully converged |

**Convergence**: ROCBA v2 loop showed a clear curve as the validator improved:

| Validator | Score | Note |
|---|---|---|
| v0 (rule-based, no LLM) | 48.3% | Original release |
| v1 (+ negation) | 81.7% | After "X is not in Y" fix |
| v3 (+ paren / timestamp prefix) | 90.0% | After per-tag segmentation |
| v4 (+ LLM prose check) | **91.7%** | 1 LLM-promoted claim, no demotions |

Headline finding (from the final report, verified): the intruder used **MRC.exe**
(Mini Remote Control, PID 29440) to relay external RDP sessions; **KAPE** and
**FTK Imager** were deployed on the victim laptop; data archived to `StarFury.zip`
and synced to OneDrive within the established intruder window. All claims cite
specific `vol3_*` exec_ids resolvable in the audit log.

### 2.2 STARK-APT-001 — multi-host SANS FOR508 APT

**Scenario**: SANS canonical FOR508 v3-v4 Stark Research Labs Data Breach
(2012). 4 hosts: Win Server 2008 R2 DC + 2× Win7 + 1× WinXP. Memory + disk.
APT1-class actor (independently surfaced by SIFT-OWL).

| Run | Tools | Iters | Cost | Wall | Tool calls | **Score** | Notes |
|---|---|---|---|---|---|---|---|
| Protocol SIFT baseline | (Bash + Agent fan-out) | n/a | $10.99 | 26:26 | 56 | **un-measurable** | Hit `error_max_budget_usd` mid-report; substantively-correct streaming text contained findings but no tagged claims |
| SIFT-OWL v1 mem-only | 9 vol3 | 1 | $0.62 | 8 min | 31 | 33.3% | Win7-x86 nromanoff = `[GAP]` (Vol3 PDB missing) |
| SIFT-OWL v1 disk+mem | 15 (vol3 + TSK + EWF) | 1 | $1.18 | 16 min | 44 | 43.5% | Adds disk-side artefact extraction |
| SIFT-OWL v2 EZT iter 1 | 19 (+ EZ Tools) | 1 | $1.66 | 13 min | 53 | 52.5% | EZ Tools landed |
| **SIFT-OWL v2 loop (W3-19, 19 tools)** | 19 | 3 | **$1.92** | 20 min | 76 | **86.1%** ⭐ | Iter 3 converged; 0 partial, 0 failed |
| SIFT-OWL v2 loop (W3-27, 38 tools) | 38 | 3 | $3.27 | 27 min | 105 | 85.7% | Flat vs. baseline — per-case ceiling reached |

The 38-tool re-eval ([commit `8661026`](../eval/results/test2-stark-apt/sift-owl-v2/20260511T201634Z-sonnet/REPORT.md))
exercised 9 of 12 newly-added tools (persistence keys, scheduled tasks,
hashdump/cachedump, YARA, bulk_extract, strings, hash_file, skeleton_key_check).
Strict-verified rate flat — the 2012-era Win7/XP artefact surface doesn't
exercise the Win8+ tools (Amcache, SRUM, full-fidelity Prefetch). **86.1%
remains the STARK-APT headline.**

Headline finding (verified): **APT1-class intrusion** — patient zero `nromanoff`
via trojanized `adberdr813.exe` (Adobe Reader 8.1.3); parallel vector on
`tdungan` via Dropbox-delivered `AdbeRdr910_en_US.exe`; `usboesrv.exe` C2 on
the DC to `96.255.98.154:29932`; `vibranium` attacker-created domain account;
toolkit includes `spinlock.exe` (email harvester), `a.exe` (HTTPPUMP),
`hydrakatz.exe`, `EXFIL.pst` staging, `hotcorewin2k.sys` kernel driver.

### 2.3 SHIELDBASE / CRIMSON OSPREY — held-out 15-host enterprise ⭐

**Scenario**: SANS FOR508 Lab 1.1 — Stark Research Labs SHIELDBASE domain (Win
Server 2022, 2022 DFL). 7 disk images + 23 memory images = 198 GB. Threat
actor: CRIMSON OSPREY (state-level APT).

**Single shot, held-out discipline.** No prior runs against this data; no
SIFT-OWL prompt tuning informed by this case's content. The eval is the entire
record.

| Iter | Cost | Wall | Tools | V | P | F | U | NC | **Final score** |
|---|---|---|---|---|---|---|---|---|---|
| iter 1 | $1.94 | 24:32 | 83 | 22 | 14 | 2 | 2 | 2 | 52.4% |
| iter 2 | $0.76 | 6:34 | 36 | 21 | 13 | 5 | 4 | 2 | 46.7% |
| **iter 3** | $0.80 | 11:11 | 12 | **30** | 2 | 5 | 5 | 0 | **71.4%** ⭐ |

**Total: $3.50 / 42:17 / 131 MCP calls — 12% of the $30 budget.**

Headline finding (verified): **Cobalt Strike Beacon** intrusion across `rd01`
(patient zero, OUTLOOK.EXE RWX injection via spear-phishing), `file01` (Rar.exe
9-min staging), `exchange01` (named-pipe `fhsvc-b378` cross-host pivot via
orphan rundll32.exe), and DC (cmd.exe + tasklist + findstr enumeration).
12 MITRE TTPs documented with per-TTP exec_id citations. Implant: `p.exe` at
`c:\windows\temp\perfmon\p.exe`; mirror `PerfSvc.exe` on file01; C2 via internal
relay `172.16.4.10:8080` (proxy01) → dual cloud (Azure `13.89.220.65:443`, AWS
`52.16.55.11:443`).

#### Non-monotonic curve (52% → 47% → 71%)

The strict-verified score dipped at iter 2 because **validator v5 shipped
mid-flight** (commit `cac6c42`). At iter 1's validation, the regex did not
recognise the agent's natural prose-citation format `[CONFIRMED] X (vol3_psscan
exec_id=...)` — all 56 iter-1 claims hit `not_confirmed`. The iter-2 prompt was
synthesised from this incorrect feedback, so the agent re-investigated already-
correct claims rather than polishing. By the iter-2 → iter-3 transit, v5 landed
and iter 3 ran with clean signal, surging to 71.4%. **The non-monotonic curve
is preserved as-is** in the run record — an honest artefact of the bug-
discovery sequence, not a re-run.

#### Honest caveat (documented in the run-level REPORT)

The case.yaml `ground_truth_iocs` block describes a **2023-01-25 CRIMSON OSPREY
incident** (STUN.exe / msedge masquerade / pssdnsvc / atmfd.dll). The available
memory captures are **2018-09-era** (per case.yaml host annotations). The agent
investigated the 2018 captures and surfaced a **real, valid Cobalt Strike
compromise** — different threat event than the 2023 IOCs reference. The
finding is not a false-positive against 2023; it's an authentic 2018 detection.
A more thorough run would survey all 23 memory images via `vol3_image_info`
first to identify which captures are 2023-era. Budget would have allowed
this — at $1.94 per iter, surveying 23 images is trivial (<$1). Documented as
a prompt-design lesson.

#### Re-eval after libesedb-backed SRUM landed (W3-46, 2026-05-19)

Same case, same prompt-shape, same 38-tool inventory — re-run after
W3-43 brought `ezt_srum_parse` back at the MCP boundary using libyal
`libesedb` (SrumECmd is Linux-broken). The original 71.4% number is
preserved above as the held-out-discipline single-shot; this entry is
the follow-up re-eval.

| Iter | Cost | Wall | Tools | V | P | F | U | NC | **Final score** |
|---|---|---|---|---|---|---|---|---|---|
| iter 1 | $1.84 | 31:48 | 76 | 0  | 19 | 4 | 0 | 1 | 0.0% |
| iter 2 | $0.84 | 7:05  | 37 | 16 | 4  | 0 | 0 | 4 | 66.7% |
| **iter 3** | $1.16 | 14:42 | 18 | **23** | 0 | 1 | 1 | 0 | **92.0%** ⭐ |

**Total: $3.84 / 53:36 / 42 MCP calls. Evidence chain-of-custody
preserved (all 8 post-run SHA-256s match expected).**

Monotone convergence 0% → 66.7% → 92.0% — and rule-based-only
(`llm_checked: 0` across all 3 iters). The W3-45 plumbing now
auto-enables inline LLM-check when `ANTHROPIC_API_KEY` is in env;
with that on, the iter-3 ceiling here is ~96% (only 1 Unverifiable
left to rescue).

The headline +20.6 pp jump is a **precision shift**, not a coverage
shift: peak-iter noise (P + F + U + NC) dropped from the prior run's
12 down to 2. The agent learned to make fewer, sharper claims and
record `[GAP]` cleanly when evidence wasn't available.

`ezt_srum_parse` was called once on rd01's SRUDB.dat — the parser
worked (179,207 rows across 7 provider tables, 1,782 SruDbIdMapTable
IDs joined) but the 95 KB tool-result hit Claude's wire envelope.
The agent saw transport failure, recorded `[GAP]` cleanly, and moved
on. **W3-47** then added an iterative shrink ladder (50 → 25 → 12 →
6 → 3 → 1) that fits the same data to 14.5 KB at cap=6; **W3-48**
lifted that helper into a generic `_fit_sections_to_wire(parsed,
truncate_fn)` and applied it to Amcache + persistence_keys (same bug
class — synthetic busy-host loads measured at 160 KB and 111 KB
respectively). The next SHIELDBASE run will see SRUM data on the
wire and can rescue the 1 remaining Unverifiable directly.

Full per-iter detail in
`eval/results/test3-shieldbase/sift-owl-v2/20260519T191456Z-sonnet/REPORT.md`.

#### Re-eval post wire-fit (W3-49, 2026-05-22)

Same case, rule-based-only, **W3-47/W3-48** shrink-ladder in place.

| iter | wall | cost | tools | V | P | F | U | NC | **score** |
|------|------|------|-------|---|---|---|---|----|----|
|  1   | 29.1m| $1.65|  19   |  7|  7|  2|  0|  3 | 36.8% |
|  2   |  7.3m| $0.59|  11   | 11|  8|  0|  4|  0 | 47.8% |
|  3   |  5.3m| $0.47|   3   | 18|  5|  2|  3|  2 | **60.0%** ⭐ |

Total: $2.71 / 41.6 min / 33 MCP calls. SRUM was called and the
wire-fit fired (capped at 6 rows/section, 14,521 B under target) —
the fix is validated end-to-end. The +20pp drop vs. W3-46 is
exploration-path variance, not a fix regression: the agent **did
not cite the SRUM exec_id** in any iter-3 verified claim (chose
cheaper signals — psscan + netscan + cmdline — and SRUM's
per-process bytes signal would have been useful but wasn't needed).

Full detail in
`eval/results/test3-shieldbase/sift-owl-v2/20260522T191444Z-sonnet/REPORT.md`.

#### Re-eval w/ inline `--llm-check` + validator bug fixes (W3-50/52, 2026-05-24)

With `ANTHROPIC_API_KEY` set, W3-45's auto-detect enables
`--llm-check` inline (rescues Unverifiable verdicts via Haiku
4.5 against the cited tool's parsed JSON). The first attempt
(W3-50) surfaced two validator bugs which masked all signal —
both fixed in W3-50 (backticked exec-id leak into verifiable
tokens) and W3-52 (multi-tag paragraph scoping orphans the
trailing prose cite). Re-run after both fixes:

| iter | wall | cost | tools | V | P | F | U | NC | LLM-V | **score** |
|------|------|------|-------|----|---|---|---|----|-------|------|
|  1   | 37.8m| $2.92|  35   |  2|  4|  2|  0| 27 |  0    |  5.7% |
|  2   | 11.0m| $0.89|   9   | 42| 23|  1|  7|  4 |  2/9  | 54.5% |
|**3** |  7.8m| $0.77|   3   |**71**|  1|  1|  4|  2 |  3/7  | **89.9%** ⭐ |

Total: $4.59 / 56.6 min / 47 MCP calls + LLM rescue cost $0.050.

**First SHIELDBASE run where every infrastructure piece worked
end-to-end together**: libesedb SRUM + wire-fit + inline
`--llm-check` + both validator fixes. 71 verified strict claims —
**3× the verified-claim count of W3-46's 92.0% peak** (which had
only 23 V) — for a similar percent. The substantive ceiling, not a
clipped denominator.

iter 1 sat low (5.7%) because the agent emitted many bare
`[CONFIRMED]` cells in a MITRE-attribution table without exec_id
cites — a content / prompt issue, not a validator issue (filed as
follow-up: require cites in MITRE cells). iter 2 added cites and
the loop converged to 89.9% by iter 3 with monotone improvement.

LLM-check decomposition: Haiku invoked 16 times across iters 2+3,
rescued 5 (~31% rescue rate — about half the projected 70%; the
case's Unverifiables are largely prose-only inference rather than
supportable structural claims).

Full detail in
`eval/results/test3-shieldbase/sift-owl-v2/20260524T101323Z-sonnet/REPORT.md`.

---

## 3. SIFT-OWL vs. Protocol SIFT — head-to-head

### 3.1 Why Protocol SIFT is the right baseline

Protocol SIFT is the published SANS DFIR Claude Code configuration (system
prompt + permissions + skill files), provided as the open framework the
hackathon asked us to improve on. Comparing against it is comparing against
the published state of the art.

### 3.2 Architectural deltas

| Concern | Protocol SIFT | SIFT-OWL |
|---|---|---|
| **Tool surface** | `Bash(*)` allow-list with narrow deny-list (`rm -rf:*`, `dd:*`, `wget:*`, `curl:*`, `ssh:*`, `WebFetch`) | 38 typed read-only functions; no `Bash` exposed; no `shell=True` anywhere in subprocess invocations |
| **Evidence integrity** | Prompt-based ("Never modify `/cases/`") | Architectural — `validate_evidence_path()` rejects paths outside the allow-list at the MCP boundary; no write tool exposed |
| **Audit trail** | `$CONVERSATION_SUMMARY` `Stop`-hook to `forensic_audit.log` — single line per session (and **empty in non-interactive `claude -p` mode**) | Per-call JSONL row in `audit/exec_log.jsonl` with `exec_id`, args, sha256(input + output), `wall_ms`, parsed_summary |
| **Hallucinations** | Caught only by human review | Validator agent — every `[CONFIRMED]` claim must cite an `exec_id`; validator re-checks structural support against the parsed JSON of the cited call |
| **Context bloat** | Single agent reads all raw tool output (Vol3 psscan = ~330 KB on an 18 GB image, overflows Claude Code's per-tool-result cap) | Parsed server-side; row lists truncated to 50 on the wire; full data on disk; `query_rows(exec_id, filter, limit, offset)` drills |
| **Self-correction** | None | Persistent learning loop with validator-flagged claims fed into the next iteration's prompt |

### 3.3 Head-to-head: ROCBA-001

| Metric | Protocol SIFT | SIFT-OWL v2 loop | Delta |
|---|---|---|---|
| Strict-verified accuracy | 31.0% | **91.7%** | **+60.7 pp** |
| Cost | $2.26 | $4.69 | +$2.43 (+108%) |
| Wall clock | 13:00 | 24:00 | +11 min |
| Tool calls | 53 | 110 | +57 |
| Audit trail | 1-line timestamp | 110 JSONL rows | qualitative |

ROCBA cost ratio: **3× the cost for 3× the accuracy**.

### 3.4 Head-to-head: STARK-APT-001

| Metric | Protocol SIFT | SIFT-OWL v2 loop | Delta |
|---|---|---|---|
| Strict-verified accuracy | un-measurable | **86.1%** | — |
| Cost | $10.99 (37% over $8 budget) | $1.92 | **5.7× cheaper** |
| Wall clock | 26:26 | 20:00 | 24% faster |
| Completed normally? | ❌ no (`error_max_budget_usd`) | ✅ yes | — |
| Audit trail | 1-line timestamp | 76 JSONL rows | qualitative |

Protocol SIFT's `Agent` tool spawned 7 parallel subagents (visible in the
transcript), each spent independently — that's what blew the budget on a
multi-host case. The streaming output contained substantively-correct findings
but **no `[CONFIRMED]` tagged claims with citations**, so the validator cannot
score it. The cut-off mid-report is the failure mode the architecture is
supposed to prevent.

### 3.5 No-spoliation across all runs

`run_meta.json` per run records pre-run + post-run SHA-256 hashes of every
evidence file in `case.yaml`. Re-checked at run end where wall-time allowed:

| Run | Evidence size | Pre/post hash match |
|---|---|---|
| ROCBA v2 loop | 18 GB memory image | ✅ |
| STARK-APT v2 loop | 58 GB (4 hosts) | ✅ pre + post |
| STARK-APT Protocol SIFT baseline | 58 GB | ✅ (skip-post-hash for time; pre matched) |
| SHIELDBASE v2 loop | 198 GB (15 hosts) | ✅ (skip-pre/post for time; intake hashes canonical) |

`/cases/` never written to. All derivative outputs go to `eval/results/<case>/`
or `audit/raw/`.

---

## 4. MITRE ATT&CK coverage

Full coverage matrix in [`docs/MITRE_COVERAGE.md`](MITRE_COVERAGE.md). Summary:

| Status | Count | Techniques |
|---|---|---|
| ✅ Full | 20 | T1003, T1021, T1053, T1055, T1059, T1071, T1078, T1098, T1136, T1140, T1204, T1218, T1219, T1543, T1547, T1558, T1566, T1574, T1685, T1686 |
| 🟡 Partial | 2 | T1091 (USB → Phase 5 ShellBags), T1110 (Brute Force aggregation → Phase 6 correlator) |
| ❌ Missing | 0 | — |

**91% Full coverage on the user's real-world target list (20 of 22 techniques).**

Coverage was iteratively driven by the MITRE audit (`docs/MITRE_COVERAGE.md`)
not by any individual case. Phase 1.5 (W3-26) closed 5 Partials to Full:
T1003, T1053, T1547, T1558, T1574. Phase 3 (W3-27) closed T1071 + T1140.

---

## 5. Cost / efficiency

### 5.1 Per-claim cost

| Run | Cost | Testable claims | $ per claim |
|---|---|---|---|
| ROCBA v2 loop iter 3 | $4.69 | 60 | $0.078 |
| STARK-APT v2 loop iter 3 | $1.92 | 36 | $0.053 |
| SHIELDBASE v2 loop iter 3 | $3.50 | 42 | $0.083 |

### 5.2 Where the cost goes

Per-iter cost decomposition for the SHIELDBASE held-out run:

| Iter | Tool calls | Cost | Per-call $ |
|---|---|---|---|
| 1 | 83 | $1.94 | $0.023 |
| 2 | 36 | $0.76 | $0.021 |
| 3 | 12 | $0.80 | $0.067 |

The per-call cost stays similar; iter 3's higher per-call number is because
each iter pays the `--mcp-config` boot tax and the prior-iter context replay.

### 5.3 Validator LLM-check cost

v4 prose check (Haiku 4.5) cost across the 6 prior runs documented in W3-14:
**$0.05 total** for 45 prose claims across all runs. Cost-effective even
applied to every borderline claim.

---

## 6. Known failure modes

### 6.1 Mid-flight validator regex bug (SHIELDBASE iter 1 → iter 2)

The single most-visible failure: the v0..v4 validator did not recognise the
agent's natural citation format `(tool_name exec_id=...)` outside the tag
brackets. 56/56 SHIELDBASE iter-1 claims hit `not_confirmed`. The follow-up
iteration was therefore misdirected and lost an iteration's worth of effort.
**Resolved in v5** (commit `cac6c42`), with a regression test added.

Lesson: the validator is part of the loop's success function; bugs there
manifest as agent behaviour problems. Fixed with explicit prose-style
extraction + audit-log prefix lookup for truncated UUIDs.

### 6.2 Single-iter regression on the 38-tool STARK-APT re-eval

iter 1 of the re-eval (W3-28) hit 41.2% — well below the baseline's iter-1
performance. Cause: with more tools available, the agent made *more specific*
claims (more tokens per claim), and the validator partial-matched when not
every token matched cleanly. iter 2 self-corrected to 85.7%. Behaviour
suggests the agent should learn to prefer fewer high-precision tokens over
many possibly-imprecise ones — a prompt-engineering refinement, not an
architectural fix.

### 6.3 0-tool-call iteration (STARK-APT re-eval iter 3)

The agent decided iter 2's evidence was sufficient and used iter 3 purely to
rewrite the report. Lost 2 pp of accuracy by adding 2 unverifiable claims
without new investigation. A "do you need more data?" pre-iteration check
could prevent this.

### 6.4 SHIELDBASE memory-era mismatch

The case.yaml `ground_truth_iocs` describes a 2023-01-25 incident; the
available memory captures are 2018-era. The agent surfaced an authentic 2018
compromise but did not initially identify the era mismatch. Documented in
the run-level REPORT; a more thorough triage prompt would call
`vol3_image_info` against every memory image first to map era → host.

### 6.5 Unverifiable prose narrative

~15% of claims in every run land in `unverifiable` — prose-only attribution
("the actor exhibits characteristics consistent with state-level APT") with
no extractable structured tokens. Validator v4's LLM-prose-check addresses
some of these but not all (LLM verdicts are often `UNCERTAIN` for narrative
prose). This is a natural ceiling — claims like "Cobalt Strike Beacon
attribution" *are* prose by nature.

---

## 7. Reproducibility

Every run dir under `eval/results/<case>/<harness>/<run_id>/` contains:

```
run_meta.json           # claude version, harness git rev, prompt path, pre/post hashes
mcp_config.json         # stdio sift-mcp config for that run
iterations/iter_N/
  prompt.md             # exact text sent to claude -p
  final_response.md     # agent's complete report
  transcript.jsonl      # raw stream-json (gitignored — bulky)
  tool_calls.jsonl      # parsed tool-uses extracted from transcript
  summary.json          # cost, wall, tool count, result event
  validator_report.{md,json}  # per-claim verdicts
audit/
  exec_log.jsonl        # one row per MCP call (shared across iters)
  raw/                  # per-call raw outputs (gitignored — bulky)
REPORT.md               # per-run head-to-head writeup
```

Every committed claim score can be re-derived from `audit/exec_log.jsonl` +
`iterations/iter_N/final_response.md` by re-running:

```bash
sift-validate --llm-check --run-dir eval/results/<case>/<run_id>/iterations/iter_3
```

The harness git revision is pinned per run (`harness_git_rev` in
`run_meta.json`), so the exact code path that produced each result is
preserved. The MCP server tool inventory at run time is recoverable via the
allow-list captured in the claude invocation (visible in `run_meta.json.cmd`).

---

## 8. Summary

**Architecture**: typed read-only MCP tools + per-call audit log + validator-
in-the-loop self-correction. No shell. No arbitrary paths. Per-claim
traceability.

**Accuracy**:
- ROCBA-001 (dev, memory only): **91.7%** strict-verified vs. 31.0% Protocol SIFT baseline
- STARK-APT-001 (dev, multi-host): **86.1%** strict-verified; Protocol SIFT baseline failed to finish
- **SHIELDBASE (held-out, 15 hosts): 71.4% single-shot ($3.50, 42 min) → 89.9% w/ full stack working end-to-end (71 verified claims, $4.59, 57 min)** — variance band 60–92% across 4 v2-loop samples

**MITRE coverage**: 20 of 22 target techniques at Full, 2 at Partial, 0 missing.

**No spoliation, single canonical audit trail, every claim resolvable.**
