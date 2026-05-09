# SIFT-OWL v1 prompt — ROCBA-001

> Injected as the **first user message** to Claude Code. The agent has been
> launched with `--strict-mcp-config` pointing at the SIFT-OWL MCP server,
> and the following built-in tools are explicitly **denied**: `Bash`, `Edit`,
> `Write`, `Read`, `NotebookEdit`, `WebFetch`, `WebSearch`, `Agent`, `Skill`,
> `AskUserQuestion`. The only callable tools are the 10 typed functions
> registered by the `sift-owl` MCP server (9 forensic + 1 query helper).

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

You have **no shell access**, **no filesystem access**, and **no web access**. The only
operations available to you are the 10 MCP tools described below. Each forensic call
returns structured JSON with an `exec_id` you must cite for every claim derived from it.

## Your task

Conduct a full memory-only investigation of the Rocba-Memory.raw image and answer all
five investigation goals:

1. **G1** What key projects did Fred have access to?
2. **G2** What was stolen?
3. **G3** Where was it transferred to (cloud / USB / network share / etc.)?
4. **G4** How was it stolen (tooling / technique)?
5. **G5** When did the activity occur (correlate with break-in window)?

## Tool inventory (10 tools)

The 9 forensic functions each take `image: str` and return:

- `exec_id` — unique ID of this tool execution. **Cite this for every claim.**
- High-signal aggregates (`count`, `by_image`, `foreign_ip_counts`, etc.).
- A **truncated row sample** (first 50 rows by default), plus:
  - `<rowkey>_total` — actual total row count
  - `<rowkey>_truncated` — `true` when the sample is a subset

| Tool | Plugin | Use for |
|---|---|---|
| `vol3_image_info` | `windows.info` | OS profile + capture time anchor |
| `vol3_psscan` | `windows.psscan` | All processes incl. hidden / exited (rowkey: `processes`) |
| `vol3_pstree` | `windows.pstree` | Parent/child relationships (rowkey: `nodes`) |
| `vol3_cmdline` | `windows.cmdline` | Command-line args per process (rowkey: `rows`) |
| `vol3_netscan` | `windows.netscan` | TCP/UDP connections (rowkey: `connections`) |
| `vol3_filescan` | `windows.filescan` | File objects in pool memory (rowkey: `files`) — slowest |
| `vol3_malfind` | `windows.malfind` | RWX/MZ injection (rowkey: `findings`) |
| `vol3_svcscan` | `windows.svcscan` | Services + drivers (rowkey: `services`) |
| `vol3_userassist` | `windows.registry.userassist` | Explorer execution log (rowkey: `entries`) |

The 10th tool drills into the full row list of any prior call:

- `query_rows(exec_id, filter_field?, filter_value?, limit=50, offset=0)`
  - `exec_id` — from a previous `vol3_*` call
  - `filter_field` — e.g. `pid`, `image`, `name`, `foreign_addr`, `process`
  - `filter_value` — case-insensitive substring for strings, exact for numbers
  - Returns `total_rows`, `matched_rows`, `returned_rows`, `rows`

**Patterns the agent should use:**

- After `vol3_psscan`, drill: `query_rows(<psscan_exec_id>, "image", "MRC")`
- After `vol3_filescan`, search: `query_rows(<filescan_exec_id>, "name", "StarFury")`
- After `vol3_netscan`, find a specific IP: `query_rows(<netscan_exec_id>, "foreign_addr", "81.30.144.115")`
- Paginate: `query_rows(<exec_id>, limit=50, offset=50)`

A reasonable triage sequence:

1. `vol3_image_info` — confirm OS profile + capture time.
2. `vol3_psscan` + `vol3_pstree` — process discovery; drill suspicious PIDs via `query_rows`.
3. `vol3_cmdline` — command lines; drill specific PIDs via `query_rows`.
4. `vol3_netscan` — exfil destinations; drill non-cloud foreign IPs via `query_rows`.
5. `vol3_filescan` — recently-cached files; drill by filename substring (project names, .zip, .pst, ...) via `query_rows`.
6. `vol3_userassist` — Explorer-driven execution per user hive (often returns full data inline).
7. `vol3_svcscan` — services for persistence; drill non-system binary paths.
8. `vol3_malfind` — code injection; triage hits manually.

## Reporting requirements

Produce a final report **as your last message text**. For every claim, **tag it explicitly**:

- `[CONFIRMED — exec_id ...]` — observed in tool output. Cite the `exec_id`.
- `[INFERRED — exec_id ...]` — derived from observed evidence with explicit reasoning.
- `[HYPOTHESIS]` — plausible but not yet supported.
- `[GAP]` — flag what's unknown and what evidence would resolve it.

If you encounter ambiguity, do not hallucinate — flag the gap.

When you are done, end with the line `SIFT-OWL RUN COMPLETE`.
