# ROCBA-001 re-eval with W3-55 prompt fix — `20260612T073440Z-sonnet`

> Second ROCBA disk + memory run. Same case, same prompt-rocba-001.md
> as W3-54 — but now with the **W3-55 citation-discipline paragraph**
> forbidding the section-header `**[CONFIRMED]**` anti-pattern that
> cost W3-54 iter 1 19 NC verdicts. All four W3-54/56/57 validator
> bug fixes are also in place.

## Headline

| Iter | Cost | Wall | MCP calls | V | P | F | U | NC | LLM-V | **Strict-verified** |
|---|---|---|---|---|---|---|---|---|---|---|
| iter 1 | $1.46 | 23.4 m | 18 | 18 | 11 | 0 | 1 | 3  | 2 | 54.5% |
| iter 2 | $0.57 | 7.5 m  | 9  | 28 | 0  | 1 | 0 | 0  | 1 | 96.6% |
| **iter 3** | $0.22 | 2.2 m | **0** | **29** | 0 | 0 | 0 | 1  | 2 | **96.7%** ⭐ |

**Total: $2.24 / 33 min / 32 MCP calls.** Evidence chain-of-custody
preserved. **Best ROCBA result on record.**

Monotone convergence 54.5% → 96.6% → 96.7%. iter 3 made **0 MCP
calls** — just refined the report against validator feedback,
removing iter 2's single Failed verdict (a methodological note —
`offset=null` — that wasn't a token in the partition-table JSON).
LLM-check fired 6 times across the three iters, rescued **5**
(83% rescue rate).

## What just happened — the W3-55 prompt fix worked exactly as scoped

Comparison against the W3-54 raw run on the same case:

| Metric | W3-54 (no prompt fix) | W3-58 (this) | Delta |
|---|---|---|---|
| Peak strict-verified | 23.7% raw / 63.2% post-fix retro | **96.7% raw** | **+33.5 pp over post-fix retro** |
| Peak verified-claim count | 9 (raw) / 24 (retro) | **29** | +5 over retro-best |
| Iter 1 NC verdicts | 19 | **3** | −16 (section-header issue eliminated) |
| Iter 2 NC verdicts | 17 (raw) / 0 (retro) | **0** | matches retro |
| Loop terminated | iter 2, no-improvement | iter 3 (max-iter) | proper convergence |
| Total cost | $3.34 | **$2.24** | −33% |
| Total wall | 112 min | **33 min** | −71% |

The 19 iter-1 NCs from W3-54 collapse to 3 — the citation-discipline
paragraph eliminated the section-header `**[CONFIRMED]**` anti-pattern
the agent emitted under the prior prompt. iter 2 then converged
sharply (28/29 verified, 1 Failed); iter 3 cleaned up the Failed and
landed at 29/30 = 96.7%.

## Comparison vs. all prior ROCBA runs

| Run | Build state | Evidence | Strict-verified peak | Verified claims |
|---|---|---|---|---|
| ROCBA v1 single-pass | v4 | memory only | 57.1% | 30/52 |
| ROCBA v2 loop iter 3 | v4 | memory only | **91.7%** | — |
| ROCBA v2 W3-54 (raw) | v6 | memory + disk | 23.7% (early-term) | 9/38 |
| ROCBA v2 W3-54 (post-fix retro) | v7 | memory + disk | 63.2% iter 2 | 24/38 |
| **ROCBA v2 W3-58 (this)** | v7 + W3-55 prompt | **memory + disk** | **96.7% iter 3** ⭐ | **29/30** |

This run **surpasses the prior 91.7% memory-only record on the same
case** — and does so with the larger disk + memory scope. The disk
side adds substantive findings (SDelete wipe campaign, secondary
`srl-h` account, MFT-grounded file paths) that memory-only runs
couldn't have surfaced.

## Substantive findings (iter 3 verified core)

The agent reconstructed the full case spine. Highlights:

### G1 — Projects Fred had access to
- 8 SRL research documents enumerated by name + path from a single
  SDelete prefetch's `files_loaded` list — Vibranium alloy test
  results, Adamantium background, The Shield research, EarthForce
  SA-26 Thunderbolt Star Fury (.docx + .jpg), Nokia strategy, two
  Pharma business plans. All in `\USERS\FREDR\ONEDRIVE\…`.
- Hostname **SRL-FORGE** confirmed from `vol3_image_info`.

### G2 — What was stolen
- All 8 documents above (their existence at 2020-11-14T13:44:52Z
  proved by the SDelete-prefetch `files_loaded` list before
  destruction).
- SDelete was downloaded by the intruder mid-window: `SDelete.zip`
  in `\Users\fredr\Downloads\`, inode 477601, with a
  `Zone.Identifier` ADS confirming web-download provenance, plus a
  paired `SDelete.lnk` shortcut at inode 477882.

### G3 — Transfer channel
- **Inbound RDP from two external IPs at capture time**:
  `81.30.144.115` (59 connections) and `213.202.233.104` (54
  connections) → local `192.168.1.5:3389`, owned by `svchost.exe`
  PID 1248 running as `-k NetworkService -s TermService`. 4
  connections ESTABLISHED at the exact memory-capture instant —
  the operator was at the keyboard at capture time.
- **Outbound RDP pivot 2020-11-14T05:00:37Z and 05:05:33Z**: the
  `MSTSC.EXE` prefetch loaded
  `\USERS\FREDR\ONEDRIVE\DOCUMENTS\DEFAULT.RDP` — the intruder used
  a saved RDP profile from Fred's OneDrive folder to connect
  outbound. Cross-cited against UserAssist
  `Microsoft.Windows.RemoteDesktop` count=2 with the same
  timestamp.

### G4 — How (TTPs)
- **T1021.001 (RDP)** for access — TermService PID 1248.
- **T1485 / T1070.004 (data destruction / anti-forensic wipe)** via
  SDelete `0E837E93`, run 5 times in a 2:18-min window starting
  2020-11-14T13:44:52Z.
- **T1053.005 (Scheduled Task)** via SCHTASKS.EXE prefetch
  `8B6144A9`, 11 runs including a 7-task burst at
  2020-11-14T14:17:57Z (single-second indicating batch/script loop)
  — likely the cleanup / persistence step after the SDelete wipes.
- **T1136.001 (local account)** *hypothesis*: secondary `srl-h`
  account with its own fully-provisioned `\Users\srl-h\` profile
  (2,808 files, full AppData structure) and its own
  `sdelete64.exe` at inode 101249.

### G5 — When
- Inside the documented intruder window
  `2020-11-13T22:00Z .. 2020-11-16T02:32:38Z`. Four peaks:
  - **2020-11-14T05:00–05:05Z** — outbound RDP pivot
    (presumably the exfil channel)
  - **2020-11-14T13:42–13:47Z** — SDelete EULA + 5-run wipe burst
  - **2020-11-14T14:17Z** — SCHTASKS 7-task burst (post-wipe
    cleanup/persistence)
  - **2020-11-16T02:31–02:35Z** — incoming RDP from
    `81.30.144.115` + `213.202.233.104`, multiple ESTABLISHED
    sessions at memory-capture moment

## Why iter 1 still wasn't perfect

iter 1 (V=18, P=11, F=0, U=1, NC=3) — score 54.5%. The 11 Partials
are the agent overreaching on path tokens or quoting
methodological notes that aren't strictly in the tool's parsed
output. The 3 NC verdicts came from a small handful of bare
`[CONFIRMED]` tags before the agent fully internalised the
citation-discipline rule — the prompt fix mostly but not
universally eliminated the pattern in one shot. The self-correction
loop then cleaned both up by iter 2.

## LLM-check decomposition

| iter | Unverifiable | LLM checked | LLM verified | LLM rescue rate |
|---|---|---|---|---|
| iter 1 | 1 | 3 | 2 | 67% |
| iter 2 | 0 | 1 | 1 | 100% |
| iter 3 | 0 | 2 | 2 | 100% |

5 of 6 prose-only assertions rescued — Haiku found genuine support
in the cited tool's parsed output for inferential claims (e.g.,
attributing the MSTSC.EXE execution to the intruder via
absentee-during-Disney timeline reasoning) that the rule-based
extractor couldn't mechanically check.

## Take-aways

1. **The W3-55 prompt fix worked.** iter 1 NC verdicts collapsed
   from 19 → 3; the dominant failure mode of W3-54 is gone.
   Combined with the W3-54/56/57 validator fixes, the same case +
   same scope landed at **96.7% iter 3** vs **23.7% raw** in W3-54.
2. **Surpasses the prior memory-only record (91.7%) on a larger
   evidence scope.** Adding 81 GiB of disk evidence didn't dilute
   the score; it deepened the substantive findings.
3. **Cost + wall went DOWN, not up.** $2.24 / 33 min vs.
   W3-54's $3.34 / 112 min — −33% cost, −71% wall, with a higher
   score. The prompt fix made the agent more efficient; the loop
   converged in 3 iters instead of stalling at 2.
4. **The validator + agent now form a tight feedback loop.** iter 3
   made 0 MCP calls — it just edited the report to address iter 2's
   single Failed verdict ("removed `offset=null` from the
   CONFIRMED body because it's a methodological note, not a token
   in the partition table JSON"). This is the self-correction loop
   working as designed.

## Files

- Raw run audit + iterations:
  `eval/results/rocba-001/sift-owl-v2/20260612T073440Z-sonnet/`
- W3-55 prompt fix: `eval/agents/sift_owl_v2/prompt-rocba-001.md`
- Validator (W3-54/56/57): `agents/validator/{extract,validate}.py`
- Tests: `tests/test_validator.py` — 71 passing
