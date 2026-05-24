# SHIELDBASE re-eval with both validator fixes + `--llm-check` — `20260524T101323Z-sonnet`

> SHIELDBASE / CRIMSON OSPREY, 3-iter v2 loop, `ANTHROPIC_API_KEY`
> in env → W3-45 auto-detect enabled inline `--llm-check`. Both
> validator bugs from the W3-50 run fixed: bug A (W3-50) — exec-id
> in backticks leaks into verifiable tokens; bug B (W3-52) —
> multi-tag paragraph scoping orphans trailing prose cites. **This
> run is the cleanest measurement to date of the v2 loop's strict-
> verified ceiling on this case.**

## Headline

| Iter | Cost | Wall | MCP calls | V | P | F | U | NC | LLM-V | LLM-cost | **Strict-verified** |
|---|---|---|---|---|---|---|---|---|---|---|---|
| iter 1 | $2.92 | 37.8 m | 35 | 2  | 4  | 2 | 0 | 27 | 0 | — | 5.7% |
| iter 2 | $0.89 | 11.0 m | 9  | 42 | 23 | 1 | 7 | 4  | 2 | $0.031 | 54.5% |
| **iter 3** | $0.77 | 7.8 m | 3 | **71** | 1 | 1 | 4 | 2 | 3 | $0.019 | **89.9%** ⭐ |

**Total: $4.59 / 56.6 min / 47 MCP calls.** Evidence chain-of-
custody preserved (all post-run SHA-256s match expected).

iter 3 strict-verified breakdown — V/(V+P+F+U+NC) = 71/(71+1+1+4+2)
= **71/79 = 89.9%**. Monotone convergence 5.7% → 54.5% → 89.9% over
the loop. The loop ran all 3 iterations (no early-termination this
time).

## What this proves

This is the first SHIELDBASE run where every infrastructure piece
worked end-to-end *together*:

1. **libesedb-backed SRUM (W3-43)** — called, parsed 179,207 rows.
2. **Wire-fit shrink ladder (W3-47)** — fired, capped at 6 rows/
   section, 14,521 B delivered on the wire under the 25,600 B
   target.
3. **Inline `--llm-check` (W3-45)** — auto-enabled from
   `ANTHROPIC_API_KEY`, fired 16× across iters 2+3, rescued 5
   Unverifiables at a total Haiku cost of $0.050.
4. **Validator bug-A fix (W3-50)** — backticked exec-id no longer
   contaminates verifiable-token list.
5. **Validator bug-B fix (W3-52)** — trailing `(exec_id `UUID`)`
   cite correctly attached to its own claim, not the next bullet's.

Combined effect: 71 verified strict claims on a single eval —
**3× the verified-claim count of W3-46's 92.0% peak (23 claims)**.
The score is similar (89.9% vs 92.0%) but the substance is
considerably bigger.

## Comparison vs. all prior SHIELDBASE runs

| Run | Build state | Peak strict-verified | V count | Notes |
|---|---|---|---|---|
| `20260510T194945Z` | pre-W3-43 (SrumECmd disabled) | **71.4%** | 30/42 | Original held-out single-shot; v5 validator landed mid-run |
| `20260519T191456Z` (W3-46) | rule-only, SRUM available but hit wire cap | **92.0%** | 23/25 | Cleanest precision shift; SRUM `[GAP]` due to 95 KB transport |
| `20260522T191444Z` (W3-49) | rule-only, wire-fit landed | **60.0%** | 18/30 | SRUM delivered at cap=6; agent didn't cite it; variance band |
| `20260523T190903Z` (W3-50) | rule + LLM, validator bugs A+B present | **0.0%** raw / 20.7% retro | 0–6 | Both bugs masked signal; early-term |
| **`20260524T101323Z`** (this, W3-52) | rule + LLM, bugs A+B FIXED | **89.9%** | **71/79** | Largest verified-claim count to date |

Three observations from this table:

1. **The "92.0% peak" in W3-46 was driven by an unusually small
   claim count (25).** A tighter denominator with the same
   numerator → higher %. This W3-52 run has 79 claims at iter 3
   and verifies 71 — substantively much more work proven correct,
   for a marginally lower percent.
2. **The variance band on the v2 loop is now ~60–92% strict-
   verified.** Sampled four times on the same case with the same
   model + same prompt; the band is the model's exploration
   randomness.
3. **The LLM rescue rate matters.** Iter 3 here rescued 3 of 7
   Unverifiables (43%). Without `--llm-check` the iter 3 score
   would be 68/79 = 86.1%; with rescue, 71/79 = 89.9%. About 4 pp
   of upside on this run, in line with the earlier estimate
   (~10 pp on W3-49 had rescue been available).

## What the agent confirmed (iter 3)

71 verified strict claims across the full intrusion narrative.
Selected high-signal ones:

- **G1 — Initial Access**: rd01 OUTLOOK.EXE (PID 8128) carries
  RWX private VAD regions; WMI execution chain
  `WmiPrvSE.exe (PID 2876)` → `powershell.exe (PID 8712)` starting
  2018-08-30T16:43:36Z; `-s -NoLogo -NoProfile` stdin-mode flags
  on PID 5848 (T1059.001 stdin-evasion).
- **G2 — Primary Implant**: `p.exe` at `C:\Windows\Temp\perfmon\p.exe`,
  SHA-256 `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`,
  164,352 bytes; Prefetch run count 1; ~1.9 MB RWX private VAD
  region in PID 8260 (reflective DLL loading signature); 9
  rundll32 children on rd01 + 28 on file01 (process-hollowing
  pattern); 1 long-lived hollowed rundll32 (PID 15116) on mail
  server since 2018-08-31T19:47:10Z.
- **G3 — Lateral Movement**: rd01 (172.16.6.11) → file01
  (172.16.4.5) SMB; file01 active SMB to R&D + workstation
  subnets; file01 WinRM (port 5985) ×6 to 172.16.5.21; bi-
  directional pivoting across three subnets.
- **G4 — Credentials**: lsass.exe PID 772 in session 0 reachable
  by attacker's WMI chain.
- **G5 — Exfiltration**: `Rar.exe` PID 2524 on file01 from
  2018-09-05T14:43:11Z to 14:52:56Z; secondary C2 via `rubyw.exe`
  PID 1156 → `10.10.254.1:61613` (Metasploit STOMP / ActiveMQ);
  rd01 external HTTPS to Azure (`13.89.220.65:443`) and AWS
  (`52.16.55.11:443`).
- **G6 — Anti-forensic**: SDelete prefetch on rd01 (T1070.004);
  no p.exe prefetch on disk (consistent with the SDelete cleanup).

The 8 non-verified iter-3 verdicts (1 P + 1 F + 4 U + 2 NC) are
mostly minor — MITRE-table bare `[CONFIRMED]` cells without cites,
and one Unverifiable claim where Haiku correctly returned
UNSUPPORTED (the cited tool's parsed output didn't carry the
prose-only token).

## SRUM call detail

Single call this run on rd01's SRUDB.dat:

- Parser produced 179,207 rows across 7 provider tables:
  network_usage 40,596, app_resource_use 115,938, app_timeline
  21,058, network_connections 1,419, push_notifications 177,
  energy_usage_lt 19, energy_usage 0. SruDbIdMapTable: 1,782 IDs.
- Wire-fit: shrunk to cap=6 rows/section, 14,521 B fit under the
  25,600 B target.
- The agent did not cite the SRUM exec_id in any iter-3 verified
  claim (the cheap signals — psscan + netscan + cmdline —
  carried the same conclusions). SRUM's full row data remains on
  disk at `audit/raw/<exec_id>.txt` for any future `query_rows`
  drill.

## LLM-check decomposition

| Iter | Unverifiable verdicts | LLM checks fired | LLM rescued | LLM cost |
|---|---|---|---|---|
| iter 1 | 0 | 0 | 0 | — |
| iter 2 | 7 → checked 9* | 9 | 2 | $0.031 |
| iter 3 | 4 → checked 7* | 7 | 3 | $0.019 |

\* The LLM-check is invoked on each `unverifiable` verdict found in
that iter; the 9/7 are the actual invocations (some claims have
multiple prose-only assertions evaluated separately). Haiku
rescued 5/16 = 31% — about half what was projected (~70%); this
particular case's Unverifiables really are largely prose-only
inference rather than supportable structural claims.

## Take-aways

1. **First SHIELDBASE run where the whole stack works.** W3-43 +
   W3-45 + W3-47 + W3-50 + W3-52 are all exercised. 71 verified
   claims at 89.9% strict-verified is the substantive ceiling for
   this case on a 3-iter v2 loop.
2. **Bug A + Bug B fixes both load-bearing.** Pre-fix retroactive
   re-validation of W3-50 hit 23.1% / 20.7% on the two iters; this
   run with the same fixes hit 89.9% on iter 3 because the agent
   could iterate against accurate per-iter feedback (iter 1's 5.7%
   correctly informed iter 2's exploration, etc).
3. **Validator confidence: high.** Of 79 iter-3 claims, only 2 are
   NC and 1 each P/F — the remaining 4 U went through Haiku and got
   real verdicts (3 VERIFIED, 4 UNSUPPORTED-or-UNCERTAIN). Almost
   nothing is left as "the validator couldn't decide."
4. **Cost still well under budget.** $4.59 / 56.6 min / 47 MCP
   calls — 15% of the $30 budget, in line with W3-46 / W3-49.
   LLM-check added $0.05 (1% of total).
5. **Variance band remains 60–92%.** Four samples; this run sits
   at the top end with the highest substantive count.

## What's outstanding

- **Content issue, not validator**: bare `[CONFIRMED]` in MITRE
  attribution table cells (27 of iter-1's 35 confirmed claims hit
  NC for this reason). Iter 2+3 mostly self-corrected by adding
  cites — but a prompt-design tweak to require cites in MITRE
  cells would lift iter 1's floor significantly.
- **Engineering**: nothing pressing on the validator side after
  W3-50/W3-52. The LLM-check is paying off but rescue rate
  (~30%) suggests prompt tuning on the Haiku checker could lift
  it; lower priority.
