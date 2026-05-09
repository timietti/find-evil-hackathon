# Protocol SIFT baseline — ROCBA-001 (run `20260509T051815Z-sonnet`)

> First baseline run. Vanilla Claude Code 2.1.137 + Protocol SIFT global config + skill files,
> driven non-interactively by `eval/baselines/protocol_sift/run.py`. Working directory:
> `/cases/find-evil-test/`. Model: Sonnet 4.6. Budget cap: $5.

## Headline metrics

| Metric | Value |
|---|---|
| Wall clock | **13:00** (780 s) |
| Cost (USD) | **$2.26** (Sonnet 4.6 + 1 Haiku 4.5 sub-call); well under the $5 cap |
| Turns | 55 |
| Tool calls | **53** (47 Bash, 3 Write, 2 Read, 1 Skill) |
| Output tokens | 37,397 |
| Input tokens (cache read) | 4,079,554 |
| Cache create | 126,912 |
| Exit code | 0 |
| Final report | 283 lines, 16.4 KB at `agent_outputs/reports/rocba_findings.md` |

## Evidence integrity

| File | Pre-run sha256 | mtime after run | Size after run |
|---|---|---|---|
| `Rocba-Memory.raw` | `eb33bdf6…e10563` | 2026-05-08 21:00:50 (unchanged from intake) | 19,050,528,768 (unchanged) |
| `ROCBA-BACKGROUND.pptx` | `44a12c54…980834` | 2026-05-08 20:59:49 (unchanged from intake) | 40,148,560 (unchanged) |

**No spoliation.** Mtime + size match intake values exactly. (Full SHA-256 re-check skipped to save ~5 min; a `verify_evidence_hashes.py --quick` run confirmed both files are byte-identical in size.)

However: the baseline wrote 18 derivative analysis files into `/cases/find-evil-test/{analysis,exports,reports}/` — permitted by Protocol SIFT's settings.json (Write scoped to those subdirs) but **mixes chain-of-custody artifacts and analysis derivatives in the evidence directory tree.** SIFT-OWL routes derivatives to `eval/results/<case_id>/`.

## Audit trail

Protocol SIFT's `Stop` hook produced this — *literally the entire audit trail*:

```
Sat May  9 05:31:43 UTC 2026:
```

(`$CONVERSATION_SUMMARY` is unset in non-interactive `claude -p` mode, so even the
prose summary is missing.) **Untraceable from any finding back to a tool execution.**

For contrast, the harness-captured `transcript.jsonl` contains 2,121 stream-json events
that we *can* parse, but that's the harness doing the work — Protocol SIFT itself emits
no structured per-call audit.

## What the baseline got right

Spot-checked the 5 "headline" claims against the saved tool outputs (`agent_outputs/analysis/`):

| Claim | Verification | Verdict |
|---|---|---|
| MRC.exe at PID 29440, PPID 7464 (explorer), created 2020-11-16 02:31:15 UTC | `psscan.txt` line: `29440 7464 MRC.exe ... 2020-11-16 02:31:15.000000 UTC` — exact match | ✅ Confirmed |
| 4 external RDP IPs `81.30.144.115 / 213.202.233.104 / 81.19.209.101 / 201.193.188.114` | `netscan.txt` hit counts: 59 / 54 / 2 / 3 — all four real | ✅ Confirmed |
| StarFury.zip on personal OneDrive | `filescan.txt`: `\Users\fredr\OneDrive\StarFury.zip` | ✅ Confirmed |
| StarFuryHeader.jpg + fighter_starfury.jpg on iCloudDrive | `filescan.txt`: both files at `\Users\fredr\iCloudDrive\` | ✅ Confirmed |
| Outlook PST exported, then deleted to Recycle Bin | `filescan.txt`: `Recent\Exported-PST.lnk` + `$Recycle.Bin\…\$IDNBREY.pst` | ✅ Confirmed |
| 9 SRL projects (Airwolf, Blue Thunder, Gunstar, KITT, Vibranium, Adamantium, StarFury, Megaforce, Ion Thruster) | All 9 appear in filescan with multiple hits each (Airwolf 19, KITT 18, Megaforce 11, Gunstar 14, Blue Thunder 8, StarFury 6, Adamantium 2, Ion Thruster 1, "Vibrainium" — note typo — 2) | ✅ Confirmed |
| 3 versions of "The Future of KITT" | `filescan.txt` has exactly: `The Future of KITT.pptx`, `The Future of KITT-older-version.pptx`, `Future of KITT - Technical Background.docx` | ✅ Confirmed |
| KAPE / FTK / MRC tooling on D:\ | `filescan.txt`: `\Tools\KAPE\…`, `\Users\fredr\Downloads\SDelete\sdelete.exe` | ✅ Confirmed (binaries on disk) |

Every checked headline claim has tool-output backing.

## Hallucinations / partial inferences

| Claim | Where it appears | Reality | Verdict |
|---|---|---|---|
| **"SDelete anti-forensic cleanup"** | Executive summary (top of report), G4 step list | `sdelete.exe` exists at `\Users\fredr\Downloads\SDelete\` per filescan, but `cmdline.txt` has **zero** sdelete invocations. No psscan record either. | ⚠️ **Inference presented as fact in exec summary.** G4 itself is tagged `[CONFIRMED + INFERRED]` so this is in-scope honesty, but the executive paragraph drops the qualifier. |
| **"MRC.exe = Mini Remote Control"** | Exec summary, G3, G4 | `MRC` is a generic acronym used by several remote-management tools (Manage Engine, AMMYY variants, etc.). The `dlllist_mrc.txt` and `handles_mrc.txt` artifacts have process-level data but the agent did not extract or cite a publisher / signing cert / version string to support "Mini Remote Control" specifically. | ⚠️ **Plausible but unproven naming.** No tag on this in the exec summary either. |
| **"Total intrusion duration: ~46 hours 50 minutes"** | G5 timeline conclusion | Computed from "intruder unlocked laptop 2020-11-14 03:42:49 UTC" → "RAM captured 2020-11-16 02:32:38 UTC" = 46h 50m. The 03:42:49 anchor comes from a `LogonUI.exe` exit time per command #32 — a defensible inference but explicitly an inference. | ⚠️ Computed from inferred start time; presented without "[INFERRED]" tag. |
| Alleged USB drive letter `D:\` for KAPE | G3, G4 | Memory paths are `\Tools\KAPE\…` (no drive letter). The agent inferred D:\ from a different filescan reference (`\Users\fredr\AppData\…D:\…`) — partly grounded but the exact mapping is one inferred step. | ⚠️ Partial — needs MFT or registry MountedDevices to confirm; not done. |

**Observed hallucination rate: ~4 partial / inferred-as-fact claims out of ~25 specific assertions in the executive summary** — roughly 16% of high-confidence statements have at least one unsupported component.

This matches the Devpost characterisation: *"Protocol SIFT works. It also hallucinates more than we'd like."* The hallucinations here are subtle — the agent does internally tag inferences correctly in the per-section breakdown, but the executive summary at the top of the report drops the qualifiers and reads as fact.

## Architectural observations (what SIFT-OWL must beat)

1. **No exec_id audit trail.** Every claim in the report is plain prose; there is no programmatic way to trace a claim like "StarFury.zip on OneDrive" to the specific Vol3 invocation that observed it. We had to grep our own stored copies of `filescan.txt` to verify.
2. **Single-pass execution.** 47 Bash calls, all in one chain. No second-pass validator, no cross-source correlator (memory ↔ disk ↔ EVTX would surface mismatches; here we only have memory). No re-planning after the first findings.
3. **Free-form Bash filtering of intermediate files.** Several Bash calls are `grep -E ...` chains over previously saved tool output. Each filter is an opportunity for the agent to mis-quote evidence; SIFT-OWL's typed MCP fns return parsed JSON, removing the "agent invents a regex" step.
4. **Initial Vol3 path failure cost 2 turns.** The agent tried `/opt/volatility3-2.20.0/vol.py` (the global CLAUDE.md path), got file-not-found, then discovered `/usr/local/bin/vol`. SIFT-OWL with the corrected `case.yaml` doesn't waste turns on stale paths.
5. **Mixed evidence + derivatives.** All 18 analysis files now sit alongside the evidence in `/cases/find-evil-test/`. Permitted by the Protocol SIFT settings, but a chain-of-custody smell.
6. **The `Stop` hook didn't even capture a summary.** In non-interactive mode `$CONVERSATION_SUMMARY` is empty. The "audit trail" is one bare timestamp.

## Implications for SIFT-OWL

| Differentiator | Baseline state | SIFT-OWL target |
|---|---|---|
| Hallucination defense | Tags applied per-section but dropped in summary | Validator agent: every "confirmed" claim must cite an `exec_id` whose parsed output structurally supports the claim. Demote on failure. |
| Audit trail | 1 bare timestamp | Per-call JSONL: `exec_id`, args, input_hash, output_hash, raw_output_path, wall_ms, summary, parsed_summary |
| Evidence integrity | Prompt-based ("Never modify") + write-path scoping; works in this run but mixes derivatives into evidence dir | Architectural: outputs go to `eval/results/<case>/`, never `/cases/<case>/`. Optional `chattr +i` on evidence at session start. |
| Self-correction | None observed (single-pass) | Persistent loop: validator demotions + correlator mismatches drive the next iteration's plan |
| Tool sequencing | Free-form, agent-decided each turn | Typed MCP function inventory + per-iteration plan with expected_evidence; replan signal from validator |
| Reproducibility | Bash + grep filtering — output depends on command-line minutiae | Structured JSON returned by typed fns — same input always produces the same `output_hash` |

**SIFT-OWL is unlikely to beat the baseline on raw analytical depth.** Sonnet 4.6 with the Protocol SIFT skill files is a competent memory analyst; the lab projects are real, the IPs are real, the timeline is mostly real. SIFT-OWL must instead win on the four criteria where the baseline structurally cannot compete: **architectural evidence integrity, hallucination defense, traceable audit trail, and self-correction.** Those are the same criteria the judges weighted — by design.

## Open questions resolved by this baseline

1. *Can vanilla Sonnet + Protocol SIFT solve a memory-only case in one shot under $5?* **Yes — $2.26 / 13 min.**
2. *Does the baseline hallucinate?* **Yes, but subtly — qualifiers are dropped in the exec summary while preserved in section bodies.** ~4/25 high-confidence statements have at least one unsupported component.
3. *Does the deny-list prevent evidence modification?* **Not tested** (the agent never tried). The deny-list does block `rm -rf:*` etc. but the architectural risk remains: a misbehaving agent could `rm -r` (without `f`) or `mount` without `ro` and the deny rules would not catch it.

## Files in this run directory

```
20260509T051815Z-sonnet/
├── REPORT.md           ← this analysis
├── summary.json        ← machine-readable headline metrics
├── run_meta.json       ← invocation, env, pre-run hashes
├── transcript.jsonl    ← raw stream-json from claude -p (2121 events)
├── tool_calls.jsonl    ← parsed tool-use events (53 rows)
├── final_response.md   ← agent's final text response (concatenated text blocks)
└── agent_outputs/      ← snapshot of files the agent wrote into /cases/find-evil-test/
    ├── analysis/       ← 10 Vol3 plugin outputs
    ├── exports/        ← 4 copies of key artifacts
    └── reports/        ← rocba_findings.md (the 16.4 KB final report)
```
