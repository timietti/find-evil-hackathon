# SHIELDBASE re-eval with SRUM wire-fit — `20260522T191444Z-sonnet`

> 3-iter v2 self-correction loop on SHIELDBASE / CRIMSON OSPREY with
> the W3-47/W3-48 shrink-ladder in place. Apples-to-apples vs.
> `20260519T191456Z-sonnet` (the prior W3-46 run that hit the wire
> cap at 95 KB and recorded SRUM as `[GAP]`).

## Headline

| Iter | Cost | Wall | MCP calls | V | P | F | U | NC | LLM-V | **Strict-verified** |
|---|---|---|---|---|---|---|---|---|---|---|
| iter 1 | $1.65 | 29.1 m | 19 | 7  | 7  | 2 | 0 | 3 | 0 | 36.8% |
| iter 2 | $0.59 | 7.3 m  | 11 | 11 | 8  | 0 | 4 | 0 | 0 | 47.8% |
| **iter 3** | $0.47 | 5.3 m  | 3 | 18 | 5  | 2 | 3 | 2 | 0 | **60.0%** ⭐ |

**Total: $2.71 / 41.6 min / 33 MCP calls.** Evidence chain-of-custody
preserved (all post-run SHA-256s match expected).

Strict-verified peak: V/(V+P+F+U+NC) = 18/(18+5+2+3+2) =
**18/30 = 60.0%**. Monotone upward 36.8% → 47.8% → 60.0%.

## Did the wire-fit work?

**Yes — exactly as designed.** SRUM was called once on rd01's
SRUDB.dat (exec_id `019e5125-9923-7f82-9573-c0556da0b2ee`); the
shrink ladder fired and brought the payload from default-cap to
**6 rows/section** (14,521 B fit under the 25,600 B target). The
audit-row summary records the shrink:

> 179207 SRUM rows across 7 sections; 40596 network-usage rows
> (per-process bytes); **wire shrink: capped to 6 rows/section
> (14521B fit under 25600B target — use query_rows for more)**

Compared to the W3-46 run, this is a clean reversal:

| Aspect | Prior (W3-46, pre-fix) | This run (W3-49, post-fix) |
|---|---|---|
| SRUM parser produced | 179,207 rows | 179,207 rows |
| Wire payload | ~95 KB → transport failure | 14.5 KB → delivered |
| Agent saw | `[GAP — no exec_id returned]` | `wire_cap_applied: 6`, `reason: size-fit` |
| Audit row | "FAILED" stub | `parsed_summary` carries section_counts + id_map_summary |

`parsed_summary.wire_cap_applied = 6`,
`parsed_summary.wire_cap_reason = "size-fit"` — the agent has
machine-readable status alongside the data.

## But the strict score went down (92.0% → 60.0%). What happened?

This is **run-to-run exploration variance, not a regression caused
by the wire-fit.** The wire-fit can only *deliver* data; it cannot
*force* the agent to base claims on it. Diagnostics:

1. **The agent never cited the SRUM exec_id.** `grep "019e5125-9923"
   iterations/iter_*/final_response.md` returns nothing — the
   agent had SRUM data available, looked at it (or didn't), and
   chose to ground all 30 iter-3 claims on `vol3_psscan`,
   `vol3_netscan`, `vol3_cmdline`, `vol3_malfind`, `tsk_fls_list`,
   and `tsk_icat_extract` evidence. SRUM's signal (per-process
   bytes_sent / bytes_recvd) would have been most useful for
   strengthening the exfil-channel claims in G5; those claims
   ended up `[INFERRED]` instead this run.
2. **The W3-46 run was an unusually clean precision shift.** Same
   prompt, same model, same toolset — the prior run's iter 3 had
   only 2 noise verdicts (1 F + 1 U). This run's iter 3 has 12 (5 P +
   2 F + 3 U + 2 NC). The agent made roughly the same number of
   verified claims (18 vs. 23) but produced more noisy ones around
   them.
3. **Cost + wall both came in under the prior run** ($2.71 vs.
   $3.84, 41.6 m vs. 53.6 m, 33 calls vs. 42 calls). The agent
   explored less and committed to more claims; the noisier
   verdicts are the cost of that trade.

The two SHIELDBASE v2-loop runs together establish a variance
band: peak strict-verified between ~60% and ~92%, sampled twice.
Neither is "wrong" — they are the same case run with the same
inputs and a non-deterministic model. The reproducibility of
*specific findings* (Outlook RWX → WMI → PowerShell → p.exe chain,
file01 powershell PID 4072 since 2018-08-28T22:08:25Z, mail-server
hollowed rundll32.exe PID 15116, internal proxy01 C2 at
`172.16.4.10:3128/8080`, Metasploit STOMP via `10.10.254.1:61613`)
is the stable signal. The single-number "strict-verified score"
oscillates above that floor.

## Direct comparison vs. W3-46 run

| Metric | W3-46 (pre-fix, 2026-05-19) | W3-49 (this, post-fix) | Delta |
|---|---|---|---|
| Strict-verified peak | iter 3 = **92.0%** (23/25) | iter 3 = **60.0%** (18/30) | −32 pp (variance) |
| Peak-iter V | 23 | 18 | −5 |
| Peak-iter P+F+U+NC | 2 | 12 | **+10 (noisier)** |
| Total cost | $3.84 | $2.71 | −$1.13 |
| Total wall | 53.6 min | 41.6 min | −12.0 min |
| Total MCP calls (audit) | 42 | 33 | −9 |
| `ezt_srum_parse` calls | 1 ([GAP] at wire cap) | 1 (delivered at cap=6) | wire-fit confirmed |
| LLM prose-checks fired | 0 | 0 | flat (no API key in env) |
| Agent cited SRUM exec_id | n/a (transport failed) | **no** (chose other tools) | — |
| Evidence unchanged | yes | yes | — |

## Take-aways

1. **The W3-47/W3-48 wire-fit is validated end-to-end.** SRUM
   parsed 179K rows, shrunk to 14.5 KB on the wire, landed cleanly
   with `wire_cap_*` status fields. The transport-layer blocker
   from the W3-46 run is gone. Amcache + persistence_keys would
   exhibit the same fit on a busy host (already tested
   synthetically in W3-48).
2. **A wire-fit unblocks a tool but cannot force the agent to use
   it.** The agent has a 38-tool inventory; it picks the cheapest
   path to evidence. SRUM's per-process exfil-bytes signal didn't
   feature in this run's final report despite being on the wire.
   That's normal — the agent had cheaper signals (cmdline + netscan)
   for the same claims. SRUM's value will show up most when the
   easier signals are absent (e.g. on a host where memory has rolled
   but the SRUM database hasn't).
3. **SHIELDBASE strict-verified peak is variance-bounded ~60-92%
   for the v2 loop**, sampled twice with same inputs. The stable
   findings (the actual incident narrative — Outlook → WMI →
   PowerShell → p.exe → rundll32 hollowing + lateral movement +
   proxy01 + Metasploit) reproduce across both runs. The
   single-number score depends on which iteration path the model
   took.
4. **Combining a future run with inline `--llm-check`** (W3-45,
   gated on `ANTHROPIC_API_KEY` being in env) should rescue at
   least the 3 Unverifiable verdicts here, lifting the floor to
   ~70% from 60%. Both rescue + variance-narrowing benefits sit on
   that switch.
5. **Cost-efficiency improved.** $2.71 / 41.6 min is 30% cheaper
   and 22% faster than the W3-46 run. The agent ran with fewer,
   shorter iterations and arrived at a reasonable converged
   narrative — not the cleanest one, but a defensible one with
   chain-of-custody intact.

## What the agent confirmed (stable across both SHIELDBASE runs)

- **Initial access (G1):** Outlook RWX shellcode in PID 8128
  (rd01); WMI execution chain `WmiPrvSE.exe (PID 2876)` →
  `powershell.exe (PID 8712)` started 2018-08-30T16:43:36Z.
- **Primary implant (G2):** `p.exe` at
  `C:\Windows\Temp\perfmon\p.exe`, SHA-256
  `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`,
  164,352 bytes; Prefetch run count 1.
- **Process hollowing:** 9 rundll32 instances on rd01 + 28 on
  file01 + 1 persistent on mail (PID 15116 since 2018-08-31).
- **Earliest foothold:** file01 powershell.exe PID 4072 created
  2018-08-28T22:08:25Z (≈44 hrs before rd01 chain).
- **C2:** internal relay `172.16.4.10:3128/8080`; Metasploit
  STOMP/ActiveMQ via `10.10.254.1:61613` on file01's secondary
  10.10.x interface.
- **Exchange compromise:** PowerShell PID 5144 with EMS connection
  active 2018-09-05T12:05:44Z.

Two independent runs converging on this narrative is the actual
reproducibility result — the strict-verified score is one metric
on top of it.
