# Protocol SIFT baseline — STARK-APT-001 (run `20260510T183123Z-sonnet`)

> Vanilla Claude Code 2.1.137 + Protocol SIFT global config + skill files, driven
> non-interactively by `eval/baselines/protocol_sift/run.py`. Working directory:
> `/cases/find-evil-test2/`. Model: Sonnet 4.6. Budget cap requested: $8 (overrun
> to $10.99). This is the second Protocol SIFT baseline — the first ran on
> ROCBA-001 (single-host memory).

## Headline outcome

**The baseline did not finish.** The agent hit the budget cap (`error_max_budget_usd`)
26 minutes in, while drafting the final report. It produced **no final report on
disk** — only 29 lines of streamed status updates in `final_response.md` and 27
intermediate analysis files scattered under `/cases/find-evil-test2/analysis/`
and `/cases/find-evil-test2/exports/`.

## Headline metrics

| Metric | Value |
|---|---|
| Wall clock | **26:26** (1586 s) |
| Cost (USD) | **$10.99** (37% over the $8 budget cap) |
| Tool calls | 56 (44 Bash, 7 Agent, 2 Skill, 2 TodoWrite, 1 ToolSearch) |
| Transcript lines | 2456 |
| Exit code | 1 (error) |
| Result subtype | `error_max_budget_usd` |
| Final report on disk | **none** — `/cases/find-evil-test2/reports/` empty |
| Streaming `final_response.md` | 29 lines, ad-hoc status updates only |

The agent's invocation of `Agent` subagents (7 spawns) is what blew the budget —
each spawned subagent costs roughly as much as the orchestrator and Protocol SIFT
encourages parallelism. On a 4-host case this is the obvious blast radius.

## Head-to-head with SIFT-OWL v2 loop on the same case

Compared to `eval/results/test2-stark-apt/sift-owl-v2/20260510T081103Z-sonnet/`
(canonical SIFT-OWL run on STARK-APT, 3 iterations):

| Metric | Protocol SIFT | SIFT-OWL v2 loop | Delta |
|---|---|---|---|
| **Completed normally** | ❌ no (hit budget) | ✅ yes | — |
| **Cost** | $10.99 | **$1.92** (1.06 + 0.56 + 0.30 across 3 iters) | **5.7× cheaper** |
| **Wall clock** | 26:26 | 19:57 (8:07 + 8:16 + 3:34) | **24% faster** |
| **Tool calls** | 56 | 76 (62 + 10 + 4) | More structured calls |
| **Final report on disk** | none | yes (per iteration) | — |
| **Strict-verified score (v4 validator)** | **un-measurable** (no tagged claims) | **86.1%** (31 verified / 36 testable) | — |
| **LLM prose-check cost** | n/a | $0.0063 | — |
| **Audit trail** | `forensic_audit.log` (empty in non-interactive mode) | `audit/exec_log.jsonl` with per-call exec_id, hashes, parsed summaries | qualitative |

The Protocol SIFT streaming output contains qualitatively-rich findings — vibranium
account creation, spinlock.exe identification, C2 to 96.255.98.154, etc. — but
**none of them are in [CONFIRMED]/[INFERRED] format with tool citations**, so the
validator cannot score them. This is a feature of the baseline failure mode: when
the agent gets cut off, what was already streamed has no structural integrity.

## Findings that did stream (un-verified, for context)

From the 29 lines of `final_response.md` the agent emitted before being cut off:

- **vibranium** local account present on `nromanoff`, `tdungan`, and **DC01** (Apr 3-7, 2012)
- **spinlock.exe** on three workstations (`nromanoff`, `nfury`, `tdungan` — `System32`),
  identical hash (MD5 `6bff2aebb8...`); identified as Python 2.5-compiled email
  credential harvester
- **a.exe** in tdungan's vibranium Temp dir; PDB path identifies it as **HTTPPUMP**
- **usboesrv.exe** on DC01 — KernelPro USB-over-Ethernet disguise; 3 ESTABLISHED
  connections to **96.255.98.154:29932** since 2012-03-20 — **C2 backdoor**
- **WmiPrvSE.exe PID 2508 DKOM-hidden** on nfury
- nfury **lsass** connecting to external **56.251.168.26** and **56.27.190.26** (C2)
- **`_MEI122362/`** PyInstaller directory contains the email-harvester payload
- DC01 has **IIS hosting `www.stark-research-labs.com`** with WebDavShare —
  consistent with a webshell foothold
- mailbox of `nfury` successfully harvested (20 emails, 1.5 MB)
- `RSydow` profile on tdungan with `a.exe` in Temp

These findings are substantively correct (cross-checked against the analyst-validated
SANS `precooked/redline/APT1 - IOCS/` data, which is privileged ground truth not
shown to the agent). The accuracy problem is **not** what the agent found — it's
the lack of structural support: no exec_id citations, no [CONFIRMED] tags, no
trace from claim back to the specific Bash invocation that surfaced it.

## Evidence integrity

`--skip-pre-hash` and `--skip-post-hash` were used (multi-host case; ~58 GB of
evidence; intake hashes already canonical in `intake/hashes/`). The intake hashes
remain authoritative.

Spot-check from `eval/cases/test2-stark-apt/case.yaml`:

| File | Intake SHA-256 |
|---|---|
| `win2008R2-controller-c-drive.E01` | `389ea6b4…d6db4e7e` |
| `win2008R2-controller-memory-raw.001` | `0980b543…ae770edd` |
| `win7-32-nromanoff-c-drive.E01` | `f9266213…a5a1e5b6` |
| ... (5 more, all unchanged from acquisition) | |

The baseline did write 27 analysis files into `/cases/find-evil-test2/{analysis,exports}/`
during the run — permitted by Protocol SIFT's `settings.json` (Write scoped to those
subdirs). SIFT-OWL routes all derivatives to `eval/results/<case_id>/` instead, so
the evidence directory tree stays pristine.

## Audit trail

Protocol SIFT relies on `~/.claude/settings.json`'s `Stop` hook to capture
`$CONVERSATION_SUMMARY`. In non-interactive `claude -p` mode this variable is unset,
so `forensic_audit.log` contains only a single timestamp — **literally the entire
audit trail**.

SIFT-OWL's `audit/exec_log.jsonl` for the same case run logged 76 rows, one per MCP
call, each with `exec_id`, args, input/output sha256, parsed_summary, `wall_ms`.
Every claim in SIFT-OWL's final report cites an `exec_id` that the validator can
resolve and re-check.

## Take-away

The STARK-APT comparison demonstrates three concrete failure modes of the unrestricted
shell-based approach on a multi-host case:

1. **Cost blow-up via subagent fan-out.** Protocol SIFT's `Agent` tool spawned 7
   parallel subagents; each spent independently; final cost was 37% over budget.
2. **No structured output.** When the agent gets truncated, the streamed text is
   not in a form the validator can score — there is no clean way to recover
   "what was actually confirmed" vs "what was a draft sentence in transit".
3. **No audit anchor.** `forensic_audit.log` was a single timestamp. There is no
   way to trace any finding back to the specific shell command that surfaced it.

SIFT-OWL's same-case run was **5.7× cheaper**, **24% faster**, **finished cleanly**,
and produced an **86.1% strict-verified report** with full per-claim audit anchors.
