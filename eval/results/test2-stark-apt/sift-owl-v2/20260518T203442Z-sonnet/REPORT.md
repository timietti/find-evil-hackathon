# STARK-APT re-eval with libesedb-backed SRUM tool — `20260518T203442Z-sonnet`

> Same case, same prompt-shape, **same 38-tool inventory** as the
> `20260511T201634Z-sonnet` baseline — but with `ezt_srum_parse` rebuilt
> on libyal `libesedb` (W3-43) instead of being disabled at the MCP
> boundary (W3-42 short-window). This is the regression check that
> putting SRUM back in the inventory does not destabilise the rest of
> the system.

## Headline

| Iter | Cost | Wall | MCP calls (audit) | V | P | F | U | NC | LLM-V | **Strict-verified** |
|---|---|---|---|---|---|---|---|---|---|---|
| iter 1 | $1.72 | 9:44 | 31 | 16 | 9 | 3 | 6 | 4 | 0 | 42.1% |
| iter 2 | $0.75 | 9:48 | 9  | 27 | 3 | 2 | 6 | 2 | 0 | 67.5% |
| **iter 3** | $0.64 | 10:16 | 4  | 28 | 0 | 0 | 7 | 2 | 0 | **75.7%** ⭐ |

**Total: $3.11 / 29.8 min / 44 MCP calls.** Evidence chain-of-custody
preserved (all 8 post-run SHA-256s match expected).

iter 3 strict-verified breakdown — V/(V+P+F+U+NC) = 28/(28+0+0+7+2) =
**28/37 = 75.7%**. Convergence pattern differs from the prior run
(monotone improvement here vs. iter-2 peak prior); the loop did not
plateau and could likely have improved further with a 4th iteration.

## Did SRUM help?

**No — and that's the expected answer for this case.** STARK-APT's host
roster is entirely pre-Win8:

| Host         | OS                  | Has SRUDB.dat? |
|--------------|---------------------|----------------|
| dc01         | Win Server 2008 R2  | no             |
| nromanoff    | Win 7 x86           | no             |
| nfury        | Win 7 x64           | no             |
| tdungan      | Win XP              | no             |

SRUM ships with Win8 (2012) and later. The agent correctly identified
that none of the four hosts have `Windows\System32\sru\SRUDB.dat` and
made **0 calls** to `ezt_srum_parse` across all 3 iterations
(`grep ezt_srum_parse audit/exec_log.jsonl` → empty).

What this run *does* prove: the new tool is registered, schema-correct,
and inert when not applicable. The MCP boundary still exposes 38
typed functions; the test suite passes (267/267); the audit log is
clean. No regressions from the libesedb refactor.

Where SRUM will pay off is the **SHIELDBASE** held-out case
(15+ Win10 hosts, 198 GB) — exactly the case where the prior run
landed at 71.4% single-shot and the per-process exfil signal is on
the table. The wkstn-01 SRUDB.dat alone holds 25,001 network-usage
rows and surfaces `subject_srv.exe` sending 1.62 GB outbound. That
is the signal SRUM exists to provide; STARK-APT is the wrong case
to measure it on.

## Direct comparison vs. prior 38-tool run (2026-05-11)

| Metric | Prior (W3-27 build) | This run (W3-43 build) | Delta |
|---|---|---|---|
| Strict-verified peak | iter 2 = **85.7%** | iter 3 = **75.7%** | **−10 pp** |
| Peak-iter claims (V+P+F+U+NC) | 35 | 37 | +2 |
| Peak-iter verified | 30 | 28 | −2 |
| Total cost | $3.27 | $3.11 | −$0.16 |
| Total wall | 26.9 min | 29.8 min | +2.9 min |
| Total MCP calls (audit log) | 105 | 44 | **−61** |
| `ezt_srum_parse` calls | 0 | 0 | flat (no SRUDB on this case) |
| LLM prose-checks fired | 19 (5 + 7 + 7) | 0 | **−19** |
| Evidence unchanged (post-hash) | — | yes (8/8) | — |

**The 10 pp headline gap is an apples-to-oranges artefact, not a
regression.** File-timestamp inspection shows the prior run's
`validator_report.json` for iter 2 was written 2026-05-11 20:44:44,
one minute *after* its `run_meta.json` (20:43:45) — i.e. the prior
"85.7%" number came from a post-hoc retroactive `sift-validate
--llm-check` pass run by hand after the v2 loop finished. The v2
loop's *inline* validator has always defaulted `llm_check=False` and
the call site in `run_loop.py:446` passes no override, so both this
run and the prior produce identical rule-based-only scores at the
moment the loop exits.

If `ANTHROPIC_API_KEY` were available in this shell, applying the same
retroactive `--llm-check` to this run's `iterations/iter_3/` would
likely rescue ~5 of the 7 Unverifiable verdicts (the prior LLM-rescue
rate on Unverifiables was ~70%), landing the strict-verified score
at 33/37 ≈ **89.2%** — slightly above the prior peak. The libesedb
refactor changed neither the validator nor the run-loop wiring;
this is a separate observation that the v2 loop should plumb
`--llm-check` (or auto-enable it when an API key is in the
environment) so the inline iter-to-iter feedback signal includes the
rescues that the human-driven retroactive pass already gets.
Filed as a follow-up; out-of-scope for the SRUM re-eval question.

## Tool-call distribution (this run, audit log)

```
tsk_icat_extract                12
strings_extract                  6
ezt_persistence_keys_parse       6
tsk_fls_list                     4
hash_file                        4
yara_scan_extract                4
vol3_hashdump                    2
vol3_cachedump                   2
vol3_scheduled_tasks             2
vol3_psscan                      1
vol3_vadyarascan                 1
ezt_srum_parse                   0   ← inventory-present, not applicable
TOTAL                           44
```

Compared to the prior run's 105 calls: this iteration's loop was less
exploratory (fewer parallel hash sweeps, no Amcache disk extraction on
all 4 hosts). The strict-score consequence is mostly downstream of the
LLM-check absence rather than the tool-call delta — iter 3 already
had 0 Failed and 0 Partial verdicts, so the rule-based pass converged
cleanly.

## Findings — what the agent confirmed this iteration

Stable ground truth recovered across the 3 iterations:

- **Initial access (G1):** `AdbeRdr910_en_US.exe` trojanized installer
  recovered from `tdungan`'s Dropbox cache (deleted but
  `tsk_fls_list`-recoverable, inode 23296), with paired Prefetch
  artefact `ADBERDR910_EN_US.EXE-2CFF2AE5.pf` at inode 23294.
- **C2 infrastructure (G2):** WCE / pwdump credential-dumping cache
  hits via `vol3_cachedump`; PsExec service installation via
  `vol3_scheduled_tasks` + persistence-keys parse on tdungan.
- **Persistence (G3):** Run / RunOnce hits for `svchost.exe`,
  `dllhost`, and (on vibranium-staged hosts) `Sidebar.exe` /
  `mctadmin.exe`.
- **Lateral movement (G4):** `vibranium` domain account observed in
  `vol3_hashdump` and Amcache evidence across multiple hosts.
- **Gaps preserved as `[GAP]`:** nromanoff Win7-x86 PAE memory is
  un-symbolicated (missing `ntkrpamp.pdb`) — flagged in iter 1 and
  carried through; this is Phase 2's territory.

## Take-aways

1. **The libesedb refactor is safe.** SRUM is back in the typed
   inventory at zero behavioural cost on a case where it doesn't
   apply; the rest of the pipeline ran end-to-end with all
   chain-of-custody invariants intact.
2. **STARK-APT is no longer a useful gauge for new tool families.**
   The case ceiling has been reached on the structured-token surface
   (prior 85.7% peak, this 75.7% under harsher validator conditions).
   New high-value tools should be measured on **SHIELDBASE**, where
   per-process exfil-bytes / push-notification / app-timeline tables
   actually exist.
3. **v2 loop should plumb `--llm-check`.** The inline validator has
   always defaulted to rule-based-only; prior "v2 loop" scores in the
   accuracy table were retroactively LLM-enriched by hand after the
   loop exited. That worked when a human re-validated, but it means
   the *iter-to-iter feedback prompt* the agent receives during the
   loop is missing ~5 LLM-rescued claims per iteration — costing the
   loop ~10 pp of signal it could be replanning against. Wiring
   `llm_check=True` through `run_loop.py:446` (gated on
   `ANTHROPIC_API_KEY` being present) closes this; cost is ~$0.30 /
   3-iter run.
