# STARK-APT re-eval with 38-tool inventory — `20260511T201634Z-sonnet`

> Same case, same prompt-shape, **38-tool inventory** (Phase 1 + 1.5 + 3
> shipped). Validator v5 in place from the start (no mid-flight regex bug
> like SHIELDBASE saw). Direct apples-to-apples vs. the prior 19-tool
> baseline run `20260510T081103Z-sonnet`.

## Headline

| Iter | Cost | Wall | Tools called | V | P | F | U | NC | LLM-V | **Final score** |
|---|---|---|---|---|---|---|---|---|---|---|
| iter 1 | $1.91 | 9:40 | 73 | 14 | 13 | 1 | 3 | 3 | 5 | 41.2% |
| **iter 2** | $0.87 | 9:39 | 32 | 30 | 0 | 2 | 2 | 1 | 5 | **85.7%** ⭐ |
| iter 3 | $0.49 | 7:37 | 0 | 32 | 0 | 2 | 2 | 4 | 5 | 80.0% |

**Total: $3.27 / 26.9 min / 105 MCP calls.**

iter 3 made **zero tool calls** — the agent decided iter 2's evidence was
sufficient and used iter 3 purely to revise/polish the report based on
validator feedback. Lost 2 pp of accuracy by adding 2 unverifiable claims
without new investigation; a budget tweak (e.g. weighting iter 3 lower)
or a "do you need more data?" pre-iteration check could prevent this.

## Direct comparison vs. 19-tool baseline

| Metric | Baseline (19 tools, 2026-05-10) | Re-eval (38 tools, 2026-05-11) | Delta |
|---|---|---|---|
| Strict-verified peak | iter 3 = **86.1%** | iter 2 = **85.7%** | **flat (−0.4 pp)** |
| Total claims (peak iter) | 36 | 34 | flat |
| Total cost (3 iters) | $1.92 | $3.27 | **+70%** |
| Wall time (3 iters) | 20:00 | 26:54 | +35% |
| Tool calls (3 iters) | 76 | 105 | +38% |
| New tools used | n/a | 9 of 12 added | — |

**The strict-verified rate is essentially flat.** New tools added breadth
(claims about persistence keys, credential dumps, signature matches), but
the strict-verified RATE plateaued around 85-86% on this case regardless
of inventory size.

## What the agent actually used (Phase 1.5+3 tools marked ★)

```
  54   query_rows                      (drill into prior results)
  10   tsk_icat_extract
   4 ★ ezt_persistence_keys_parse      (Run keys / Winlogon / IFEO / Services from disk)
   4   tsk_fls_list
   3 ★ vol3_scheduled_tasks            (T1053 from memory)
   3 ★ vol3_vadyarascan                (T1055 memory YARA on suspect PIDs)
   3 ★ strings_extract                 (hardcoded URLs / mutex names in extracted binaries)
   3   vol3_psscan
   3   ezt_shimcache_parse
   2 ★ vol3_hashdump                   (T1003.002 local SAM)
   2 ★ vol3_cachedump                  (T1003.005 DCC2/MSCASH)
   2 ★ yara_scan_extract               (Mimikatz / Cobalt Strike / PyInstaller rules)
   1 ★ bulk_extract                    (multi-scanner full-image features)
   1 ★ hash_file                       (MD5/SHA-1/SHA-256/ssdeep)
   1 ★ vol3_skeleton_key_check         (T1558 Mimikatz patch)
   1   vol3_svcscan
   1   vol3_netscan
```

**9 of 12 Phase 1.5+3 tools exercised.** Tools NOT used: `vol3_envars`,
`ezt_task_xml_parse`, `vol3_dlllist`. (No Task XML files found; no
specific PID flagged for envars; dlllist not needed once vadyarascan
covered the same PIDs.)

## Why no material lift

Three reasons emerge from comparing the iter-by-iter outputs:

1. **The baseline was already near-ceiling on this case.** The 19-tool
   inventory could surface every implant (spinlock.exe, a.exe,
   usboesrv.exe, hydrakatz.exe) via `vol3_filescan` + `vol3_psscan` +
   `ezt_shimcache_parse`. Persistence was *inferred* rather than
   *directly observed* in the baseline, but the inferred persistence
   was correct — validator-checked.

2. **The new tools added breadth, not accuracy.** Re-eval iter 2 claims
   include things baseline missed (specific Run-key paths from
   `ezt_persistence_keys_parse`, Cobalt Strike / Mimikatz rule hits from
   `vol3_vadyarascan` and `yara_scan_extract`). But the strict-verified
   *rate* of these new claims is similar to the rate the baseline
   already had — so the overall % didn't move.

3. **STARK-APT is 2012-era — half the Phase 1.5+3 tools don't apply.**
   - `ezt_srum_parse` → SRUM is Win8+; not on this image
   - `ezt_amcache_parse` → Amcache.hve is Win8.1+; absent here
   - `ezt_prefetch_parse` works on Win7 but with reduced fidelity
   - `vol3_hashdump` / `vol3_cachedump` did surface accounts but added 0
     verified rows that weren't already evidenced by `vol3_handles` + EVTX

   The tools that DID add unique value here:
   `ezt_persistence_keys_parse`, `vol3_vadyarascan`, `strings_extract`,
   `yara_scan_extract`, `vol3_scheduled_tasks`.

## What this means

**The plateau is interesting in its own right.** It says the architecture
has reached a natural ceiling on this case where:

- Adding more tools doesn't help (the agent already finds the right things)
- The remaining 14-15% of unverified claims are mostly **prose-only attribution
  narrative** ("the attacker class is APT1") that has no extractable structured
  tokens
- The LLM-prose-check gave 5 verified bumps (matching baseline) — same
  ceiling

For a different case profile — Win10 + busy filesystem + active SRUM /
Amcache — the new tools have far more material to work with. STARK-APT's
2012 Win7-era artefact surface limits the gains.

## What's worth re-running

Phase 5 (RECmd / SQLECmd / SBECmd) won't materially help STARK-APT either —
no shellbags abuse, no browser-history evidence. Phase 5's value is on
Win10 cases like the SHIELDBASE 2018-era captures or any modern enterprise
investigation.

## Cost / value summary

- **Baseline (19 tools):**   $1.92 / 20 min → 86.1% strict-verified ← still the headline for STARK-APT
- **Re-eval (38 tools):**    $3.27 / 27 min → 85.7% strict-verified
- **Delta cost:**            +$1.35 / +7 min
- **Delta accuracy:**        −0.4 pp (flat)

**The expanded toolset is the right architectural call** — it closes
MITRE coverage gaps that STARK-APT happens not to exercise but
SHIELDBASE and future Win10 cases will. For STARK-APT specifically,
86.1% remains the headline.

## Files

```
eval/results/test2-stark-apt/sift-owl-v2/20260511T201634Z-sonnet/
├── audit/exec_log.jsonl    (105 rows, shared across iters)
├── iterations/
│   ├── iter_1/   (73 tool calls, 53 claims, 41.2% strict-verified)
│   ├── iter_2/   (32 tool calls, 51 claims, 85.7% strict-verified) ⭐
│   └── iter_3/   (0 tool calls, 60 claims, 80.0% strict-verified — report rewrite)
├── mcp_config.json
├── run_meta.json
└── REPORT.md   (this file)
```

## Headline (one line)

**STARK-APT re-eval with 38 tools: 85.7% strict-verified — flat vs. 19-tool baseline (86.1%). New tools added breadth; per-case ceiling reached.**
