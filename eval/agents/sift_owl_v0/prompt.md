# SIFT-OWL v0 prompt — ROCBA-001

> Injected as the **first user message** to Claude Code. The agent has been
> launched with `--strict-mcp-config` pointing at the SIFT-OWL MCP server,
> and the following built-in tools are explicitly **denied**: `Bash`, `Edit`,
> `Write`, `Read`, `NotebookEdit`, `WebFetch`, `WebSearch`, `Agent`, `Skill`,
> `AskUserQuestion`. The only callable tools are the 9 typed functions
> registered by the `sift-owl` MCP server.

---

You are operating as a Principal DFIR Orchestrator on the SANS SIFT Workstation.

## Case ROCBA-001 — Fred Rocba / SRL break-in & IP theft

Fred Rocba is a technical engineer hired by Stark Research Labs (SRL) on **2020-10-24** and
shipped a Microsoft Surface for remote work. He used it from home with O365, OneDrive,
Dropbox, Google Drive, iCloud, and Zoom. Browsers installed: Edge, Firefox, Chrome.
Personal identities: `fred.rocba@gmail.com`, `fred.rocba@outlook.com`, iPhone +1-339-223-3317.
Corporate email: `frocba@stark-research-labs.com`.

On **2020-11-10 morning EST** Fred and his family flew to Disney World on a planned vacation.
On the evening of **2020-11-13 EST** his residence was broken into. The intruders accessed
his SRL Surface (left logged in). Fred returned **2020-11-15 PM EST**, did not touch the
laptop, and SRL captured RAM at **2020-11-15 21:32:38 EST** (`2020-11-16T02:32:38Z`).

**Temporal alibi:** any user-driven activity inside `2020-11-13T22:00Z .. 2020-11-16T02:32Z`
that is not iCloud / Dropbox / OneDrive / GoogleDrive / O365 sync is the intruder.

## Evidence (read-only, do not modify)

- `/cases/find-evil-test/Rocba-Memory.raw` — 18 GB Windows 10 build 19041 (x64) RAM capture.

You have **no shell access**, **no filesystem access** (`Read`/`Write`/`Edit` are denied),
and **no web access**. The only operations available to you are the typed forensic
functions exposed by the `sift-owl` MCP server. Each function returns structured JSON
with an `exec_id` you must cite for every claim derived from its output.

## Your task

Conduct a full memory-only investigation of the Rocba-Memory.raw image and answer all
five investigation goals:

1. **G1** What key projects did Fred have access to?
2. **G2** What was stolen?
3. **G3** Where was it transferred to (cloud / USB / network share / etc.)?
4. **G4** How was it stolen (tooling / technique)?
5. **G5** When did the activity occur (correlate with break-in window)?

## How to use the tools

Each `vol3_*` function takes a single `image` argument and returns:

- `exec_id` — unique ID of this tool execution. **Cite this for every claim.**
- High-signal aggregates (`count`, `by_image`, `foreign_ip_counts`, etc.).
- A full row list (`processes` / `services` / `connections` / `files` / etc.) for deeper analysis.

A reasonable triage sequence (you are free to depart from it):

1. `vol3_image_info` — confirm OS profile + capture time.
2. `vol3_psscan` + `vol3_pstree` — process discovery, parent/child anomalies.
3. `vol3_cmdline` — command lines (most-revealing single source).
4. `vol3_netscan` — exfiltration destinations.
5. `vol3_filescan` — files cached in pool memory (slow — ~3 min — but covers the
   stolen-files question).
6. `vol3_userassist` — Explorer-driven program execution per user hive.
7. `vol3_svcscan` — service / driver enumeration for persistence.
8. `vol3_malfind` — code injection (slow, often false-positive on Defender / .NET).

You do not need to run all of them — choose what the case calls for and explain
why you picked the sequence you did.

## Reporting requirements

Produce a final report **as your last message text** (no `Write` is available). For every
claim, **tag it explicitly** as one of:

- `[CONFIRMED — exec_id ...]` — observed in tool output. Cite the specific `exec_id`.
- `[INFERRED — exec_id ...]` — derived from observed evidence with explicit reasoning.
- `[HYPOTHESIS]` — plausible but not yet supported.

If you encounter ambiguity, do not hallucinate — flag the gap as `[GAP]` with what
evidence would resolve it.

When you are done, end your final message with the line `SIFT-OWL RUN COMPLETE`.
