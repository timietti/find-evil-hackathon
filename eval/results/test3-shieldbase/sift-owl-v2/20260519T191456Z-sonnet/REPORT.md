# SHIELDBASE re-eval with libesedb-backed SRUM — `20260519T191456Z-sonnet`

> 3-iter v2 self-correction loop on the held-out SHIELDBASE / CRIMSON
> OSPREY case (15+ Win10 hosts, 198 GB) with the new `ezt_srum_parse`
> (W3-43, libyal `libesedb` backend). Apples-to-apples vs. the prior
> 3-iter v2 reference run `20260510T194945Z-sonnet`.

## Headline

| Iter | Cost | Wall | MCP calls | V | P | F | U | NC | LLM-V | **Strict-verified** |
|---|---|---|---|---|---|---|---|---|---|---|
| iter 1 | $1.84 | 31.8 m | 24 | 0  | 19 | 4 | 0 | 1 | 0 | 0.0% |
| iter 2 | $0.84 | 7.1 m  | 13 | 16 | 4  | 0 | 0 | 4 | 0 | 66.7% |
| **iter 3** | $1.16 | 14.7 m | 5  | 23 | 0  | 1 | 1 | 0 | 0 | **92.0%** ⭐ |

**Total: $3.84 / 53.6 min / 42 MCP calls.** Evidence chain-of-custody
preserved (all post-run SHA-256s match expected).

Strict-verified breakdown — V/(V+P+F+U+NC) = 23/(23+0+1+1+0) =
**23/25 = 92.0%**. Monotone convergence: 0% → 66.7% → 92.0%. iter 1
made 0 verified claims (every claim had a quality issue) but the
self-correction loop drained the noise across iters 2 and 3.

## Did SRUM help?

**SRUM was called, but the wire-size cap intercepted the result on
its way to the agent.** The audit log shows one successful call:

- Tool: `ezt_srum_parse` (exec_id `019e41bb-...`)
- Source: `Windows\System32\sru\SRUDB.dat` from rd01 (extracted via
  `tsk_icat_extract`)
- Parser output: **179,207 rows across 7 provider tables** —
  network_usage = 40,596 rows, app_resource_use = 115,938,
  app_timeline = 21,058, network_connections = 1,419, push = 177,
  energy_usage_lt = 19; SruDbIdMapTable resolved 1,782 IDs
  (1,141 app_path, 73 service, 393 appx_name, 173 user_sid).
- Result returned to the agent: **truncated by the wire-size limit.**
  iter 3's final response calls this out explicitly:

  > [GAP — would need: SRUDB.dat network_usage section; the parse
  > result (95 KB JSON) exceeded the tool output buffer and no
  > exec_id was returned.]

So the libesedb refactor itself works (179K rows parsed cleanly,
join with id_map populated correctly) but `_truncate_srum`'s default
of 50 rows per section produces ~95 KB of payload, which exceeds the
MCP tool-result envelope on Claude's side. The agent saw the call
fail (no exec_id), recorded a `[GAP]`, and moved on. This means the
**+20.6 pp headline improvement vs. the prior SHIELDBASE run came
from precision, not SRUM**. Engineering follow-up filed below.

## Direct comparison vs. prior 3-iter SHIELDBASE run (2026-05-10)

| Metric | Prior (W3-19/26 build) | This run (W3-43 build) | Delta |
|---|---|---|---|
| Strict-verified peak | iter 3 = **71.4%** (30/42) | iter 3 = **92.0%** (23/25) | **+20.6 pp** |
| Peak-iter V | 30 | 23 | −7 |
| Peak-iter P + F + U + NC | 12 | 2 | **−10** |
| Total claims (peak) | 42 | 25 | −17 |
| Total cost | $3.50 | $3.84 | +$0.34 |
| Total wall | 42.3 min | 53.6 min | +11.3 min |
| Total MCP calls (audit) | 41 | 42 | flat |
| `ezt_srum_parse` calls | 0 (Linux-broken pre-W3-43) | 1 (succeeded; result hit wire cap) | +1 |
| LLM prose-checks fired | 18 retroactive (4 + 5 + 9) | 0 | −18 |
| Evidence unchanged | — | yes | — |

The peak-iter precision shift is the headline: the prior run had **12
noisy verdicts** (5 Failed, 2 Partial, 5 Unverifiable) competing with
30 Verified ones; this run produced **23 Verified with only 2 noise**
(1 Failed + 1 Unverifiable). Cleaner narrative, fewer false-confidence
claims, sharper [GAP] annotation when evidence isn't available.

Even more notable: **this run got to 92% with `llm_checked: 0` on
every iteration.** The prior 71.4% peak included a retroactive
`sift-validate --llm-check` pass that rescued 9 Unverifiable claims
on iter 3 (file mtime confirms: `validator_report.json` was written
90s after `run_meta.json`). With the W3-45 plumbing, a future run
with `ANTHROPIC_API_KEY` set would auto-enable LLM-check inline; on
this run's iter 3 there is only 1 Unverifiable left to rescue, so
the ceiling here is ~96% (24/25).

## Tool-call distribution

```
tsk_icat_extract                 9
vol3_image_info                  4
vol3_psscan                      4
vol3_netscan                     4
vol3_cmdline                     4
vol3_pstree                      2
tsk_partition_table              2
tsk_fls_list                     2
ezt_evtx_parse                   2
ezt_amcache_parse                2
ezt_srum_parse                   1   ← new, hit wire cap
ezt_prefetch_parse               1
vol3_svcscan                     1
vol3_scheduled_tasks             1
ezt_task_xml_parse               1
strings_extract                  1
vol3_malfind                     1
TOTAL                           42
```

Compared to the prior run's 41 calls: identical exploration depth.
The strict-verified jump is entirely a **quality** signal, not a
coverage signal.

## What the agent confirmed

iter 3's converged narrative recovered the CRIMSON OSPREY APT chain
across rd01, file01, mail, and DC hosts. Selected ground-truth wins:

- **Initial access (G1):** Outlook RWX shellcode at PID 8128
  (rd01); WMI execution chain `WmiPrvSE.exe (PID 2876)` →
  `powershell.exe (PID 8712)` started 2018-08-30T16:43:36Z; three
  RWX private VAD regions in PID 8712 corroborating shellcode
  injection.
- **Primary implant (G2):** `p.exe` (SHA-256
  `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`,
  164,352 bytes) staged in
  `C:\Windows\Temp\perfmon\p.exe`; Prefetch run-count = 1, run time
  2018-08-30T22:15:18Z; loaded WININET / WS2_32 / DNSAPI consistent
  with HTTP C2; ~1.9 MB RWX private region in process memory.
- **Process hollowing:** 9 `rundll32.exe` instances spawned by
  PowerShell PID 5848 + p.exe (all args=null — definitive hollowing
  signature); rd01 also held a persistent hollowed `rundll32.exe`
  PID 15116 alive since 2018-08-31.
- **Lateral movement (G3):** rd01 → file01 (172.16.4.5) SMB
  ESTABLISHED, file01 → R&D and workstation subnets,
  file01 → 172.16.5.21:5985 WinRM × 6 connections, mail server
  Exchange Management Shell opened at 2018-09-05T12:05:44Z.
- **Secondary C2:** `rubyw.exe` PID 1156 on file01 with ESTABLISHED
  connection to `10.10.254.1:61613` (Metasploit STOMP / ActiveMQ).
- **Exfil staging (G5):** `Rar.exe` PID 2524 active on file01 from
  2018-09-05T14:43:11Z to 14:52:56Z; external HTTPS to Azure
  (`13.89.220.65`) and AWS (`52.16.55.11`).

The agent independently noted SRUM as the missing-data source for
the per-process exfil bytes signal — but recorded it as a `[GAP]`
rather than fabricating numbers. That's the desired failure mode.

## Engineering follow-up — SRUM wire-size cap

The current `_truncate_srum` in `mcp_server/tools/ez_tools.py` caps
each provider section at 50 rows. With 7 sections, 12+ string fields
per row, and full-resolution `app_path` values (often 80+ chars
each), the payload sums to ~95 KB which exceeds Claude Code's per-
tool-result transport limit. The agent receives a transport-layer
error and no `exec_id` to drill against.

Three options ranked by effort:

1. **Lower the default per-section cap to 10 rows + add `top_by`
   parameter.** Sorted-by-bytes for `network_usage`, sorted-by-time
   for `app_timeline`, etc. Reduces payload to ~20 KB worst-case
   while preserving the high-value signals. ~1 hour.
2. **Default-elide low-value sections** (energy_usage_lt,
   push_notifications, app_timeline) behind an `include_sections=`
   parameter; surface only network_usage + app_resource_use +
   network_connections by default. ~30 min.
3. **Return only `section_counts` + `id_map_summary` from the wrapper;
   require `query_rows` to fetch any row data.** Most ergonomic
   forced-drill pattern, mirrors how heavy plugins like `tsk_fls_list`
   handle it. ~1 hour but changes the contract.

(1) preserves the contract and gives the agent an explicit knob;
that's the recommended path. Tracked as a follow-up — not blocking
the submission since the agent already records `[GAP]` cleanly and
the case ceiling is being approached without SRUM data.

## Take-aways

1. **SHIELDBASE +20.6 pp** in strict-verified accuracy
   (71.4% → 92.0%) — and the prior 71.4% had an LLM-rescue boost
   the current run did not. Rule-based-only vs. rule-based +
   retroactive LLM. The substantive jump is the precision shift in
   the agent's claim quality, not new tool coverage.
2. **The libesedb refactor is correct at the parser layer.** 179K
   SRUDB rows parsed cleanly with full id-map resolution; the
   wire-size cap is a tool-result transport issue, not a
   correctness issue.
3. **One more eval, with `ANTHROPIC_API_KEY` set and the wire-size
   fix, should land SHIELDBASE in the mid-90s.** With LLM-check
   auto-enabled (W3-45) and `_truncate_srum` lowered to 10 rows /
   section, this case has visible headroom to ~96%+ on the strict
   scale.
4. **Evidence integrity preserved end-to-end.** All 198 GB of
   evidence images returned matching SHA-256 hashes after the run.
