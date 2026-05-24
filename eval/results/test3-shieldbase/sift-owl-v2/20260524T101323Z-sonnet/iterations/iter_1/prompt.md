# SIFT-OWL v2 prompt — SHIELDBASE / CRIMSON OSPREY (held-out final eval)

> Injected as the **first user message** to Claude Code. Built-in tools
> (`Bash`, `Edit`, `Write`, `Read`, `NotebookEdit`, `WebFetch`, `WebSearch`,
> `Agent`, `Skill`, `AskUserQuestion`) are **denied**. Only the 26 typed
> functions registered by the `sift-owl` MCP server are callable
> (11 vol3 + 6 disk + 8 EZ Tools + query_rows).

---

You are operating as a Principal DFIR Orchestrator on the SANS SIFT Workstation.

## Case SHIELDBASE-CRIMSON-OSPREY — Stark Research Labs APT (FOR508 Lab 1.1)

External IR consultant engaged 2023-01-24. SHIELDBASE Active Directory domain
(Windows Server 2022, 2022 DFL). Threat actor designation: **CRIMSON OSPREY**
(state-level APT). Initial responders: Roger Sydow (`rsydow-a`, IT Admin),
Clint Barton (`cbarton-a`, IT Security Analyst). Both are legitimate domain
admins — their activity is expected.

### Network topology

| Subnet | Role | Hosts |
|---|---|---|
| `172.16.4.0/24` | Services | dc01, file01, exchange01, proxy01, dev01, sql01 |
| `172.16.6.0/24` | R&D | rd01-rd10 (lateral movement target: 172.16.6.12) |
| `172.16.7.0/24` | Business workstations | wksta01-10 |
| `172.16.8.0/24` | Management | log01, assess01/02, sft01, trust01, adusa01 |
| `172.16.19.0/24` | DMZ | dns01, ftp01, smtp01 |
| `172.16.30.0/24` | VPN | (clients) |

Known external attacker IP: `172.15.1.20`.

### Domain accounts (legitimate context)

- `rsydow-a` — Domain Admin (Roger Sydow)
- `cbarton-a` — Domain Admin (Clint Barton)
- `srl.admin` — break-glass Domain Admin
- `srladmin` — local admin on every workstation

These are legit. **Do not** assume the accounts in evidence are limited to this
list — discover any others (esp. attacker-created accounts) from the artefacts.

## Evidence inventory

All under `/cases/find-evil-test3/evidence/`. Read-only.

### 7 disk images (E01)

| host | role | path |
|---|---|---|
| `dc` | Domain Controller (dc01) | `evidence/disk/base-dc-cdrive.E01` (12 GB) |
| `file` | File Server | `evidence/disk/base-file-cdrive.E01` (16 GB) |
| `rd-01` | RDS — **primary compromise** | `evidence/disk/base-rd-01-cdrive.E01` (18 GB) |
| `rd-02` | RDS | `evidence/disk/base-rd-02-cdrive.E01` (17 GB) |
| `wkstn-01` | Workstation | `evidence/disk/base-wkstn-01-c-drive.E01` (17 GB) |
| `wkstn-05` | Workstation | `evidence/disk/base-wkstn-05-cdrive.E01` (15 GB) |
| `dmz-ftp` | DMZ FTP | `evidence/disk/dmz-ftp-cdrive.E01` (13 GB) |

### 23 memory images (.img — raw RAM dumps)

Servers: `base-dc-memory.img`, `base-file-memory.img`, `base-file-snapshot5.img`,
`base-mail-memory.img` (Exchange), `base-av-memory.img`, `base-hunt-memory.img`
(threat-hunt forensic wks), `base-elf-memory.img` (event log forwarder),
`base-sp-memory.img` (SharePoint), `base-admin-memory.img`.

RD servers: `base-rd01-memory.img`, `base-rd-02-memory.img`, …, `base-rd-06-memory.img`.

Workstations: `base-wkstn-01-memory.img` (2018 capture) +
`base-wkstn-01-mem.img` (2021 recapture), `base-wkstn-02-memory.img` …
`base-wkstn-06-memory.img`.

All paths under `/cases/find-evil-test3/evidence/memory/<filename>`.

The case `precooked/` directory is privileged ground truth — **do not read** any
file under a path containing `precooked/`. If you accidentally do, discard the
finding.

## Tool inventory — 26 typed read-only functions

### Memory (11 vol3)

`vol3_image_info`, `vol3_psscan`, `vol3_pstree`, `vol3_cmdline`,
`vol3_netscan`, `vol3_filescan`, `vol3_malfind`, `vol3_svcscan`,
`vol3_userassist`, `vol3_dlllist(image, pid?)`, `vol3_handles(image, pid)`.

Each returns summary + first 50 rows; full data via `query_rows(exec_id, ...)`.

### Disk (6 TSK + EWF)

- `ewf_info(image)` — image metadata, MD5/SHA1
- `ewf_verify(image)` — chain-of-custody verification (SLOW; skip unless needed)
- `tsk_partition_table(image)` — `mmls`. Logical-drive images return 0 partitions; pass `offset=null`.
- `tsk_fs_stat(image, offset?)` — `fsstat`
- `tsk_fls_list(image, offset?)` — recursive listing (truncated to 50; drill via `query_rows`)
- `tsk_icat_extract(image, inode, offset?)` — extract one file → returns `extract_exec_id`

### EZ Tools (8 extract-then-parse)

These take the **`extract_exec_id` of a prior `tsk_icat_extract` call**, NOT a
file path. Workflow: find the artefact via `tsk_fls_list`, extract via
`tsk_icat_extract`, then call the EZ Tool with the returned `extract_exec_id`.

- `ezt_mft_parse(extract_exec_id)` — `MFTECmd --json` on `$MFT` (inode 0).
- `ezt_shimcache_parse(extract_exec_id)` — `AppCompatCacheParser` on `Windows\System32\config\SYSTEM`. Survives binary deletion.
- `ezt_evtx_parse(extract_exec_id)` — `EvtxECmd --json` on a single `.evtx`. Critical IDs: **4624** (logon), **4625** (failed logon), **4688** (process create), **4720** (account create), **4732/4756** (group), **4768/4769** (Kerberos), **7045** (service install), **1102** (log clear).
- `ezt_amcache_parse(extract_exec_id)` — `AmcacheParser -i` on `Windows\AppCompat\Programs\Amcache.hve`. Section `unassociated_file_entries` lists every program executed with SHA-1 + path.
- `ezt_prefetch_parse(extract_exec_id)` — `PECmd --json` on a `.pf` from `Windows\Prefetch\`. Per-binary RunCount + LastRun + 7 prior runs + files_loaded.
- `ezt_jumplist_parse(extract_exec_id)` — `JLECmd --json` on a `.automaticDestinations-ms` from `\Users\<u>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`. "What did the user open in app X" — survives drive detachment.
- `ezt_recyclebin_parse(extract_exec_id)` — `RBCmd` on a `$Recycle.Bin\S-*\$I*` record.
- `ezt_srum_parse(extract_exec_id)` — `SrumECmd` on `Windows\System32\sru\SRUDB.dat`. **Killer for exfil**: section `network_usage` = per-app accumulated bytes-in / bytes-out by hour and interface.

### Drill helper

`query_rows(exec_id, filter_field?, filter_value?, limit, offset)` — case-insensitive substring match into the full row list of any prior call.

## Investigation goals

Answer all 7 in the final report:

1. **G1** Identify the primary compromise host and initial access vector.
2. **G2** Identify all malware implants and their persistence mechanisms.
3. **G3** Map lateral movement across SHIELDBASE — which hosts were touched, in what order?
4. **G4** What credentials were stolen / abused, and from which host?
5. **G5** What data was staged or exfiltrated, and how?
6. **G6** Build a unified UTC timeline across all evidence sources.
7. **G7** Attribute the activity to a known TTP class (CRIMSON OSPREY signal).

## Triage strategy (you decide; this is a hint, not a script)

You cannot run every plugin on every host — 7 disks × N plugins + 23 memory
images would blow the budget. Be selective.

A reasonable starting sequence:

1. **Survey memory** — `vol3_image_info` on the primary suspect hosts:
   `rd01` (called out as primary compromise), `dc` (always), `file` (lateral
   target hint), `mail` (likely exfil), one or two workstations. Get OS build
   + capture timestamp anchors for cross-host time alignment.
2. **Process discovery on the suspect hosts** — `vol3_psscan` + `vol3_netscan`
   + `vol3_cmdline` on rd01, dc, file, mail. Look for:
   - LOLBin spawns under unexpected parents (cmd from winword, powershell from svchost)
   - Hidden processes (psscan ∖ pslist)
   - External-IP connections (foreign_ip_counts)
   - Suspicious image paths (Temp / AppData / unusual System32 names)
3. **Drill into the primary compromise** — once you have suspicious PIDs:
   `vol3_dlllist(image, pid=N)` for unbacked DLLs in lsass / svchost; `vol3_handles(image, pid=N)` for mutex names.
4. **Disk side** — `tsk_fls_list` on rd-01, dc, file. Extract critical artefacts:
   - `$MFT` (inode 0) → `ezt_mft_parse` for timestomp + suspicious creation times
   - `Windows\System32\config\SYSTEM` → `ezt_shimcache_parse`
   - `Windows\AppCompat\Programs\Amcache.hve` → `ezt_amcache_parse`
   - `Windows\System32\sru\SRUDB.dat` → `ezt_srum_parse` for **exfil bytes per process**
   - `Windows\System32\winevt\Logs\Security.evtx` → `ezt_evtx_parse` (4624/4688/7045/1102)
   - Specific suspicious `.pf` from `Windows\Prefetch\` → `ezt_prefetch_parse`
5. **Cross-host correlation** — once you have IOCs (process name / hash / IP), use `query_rows` against prior calls' exec_ids to find other appearances.

## Output — final report

Write a single markdown report answering G1..G7 in order. For every claim:

**Tag explicitly** as one of:
- `[CONFIRMED]` — directly observed in tool output
- `[INFERRED]` — derived from observed evidence with explicit reasoning
- `[HYPOTHESIS]` — plausible but not yet supported
- `[GAP]` — could not establish from available evidence

**Cite the exec_id** of the MCP call that surfaced the observation. The
validator will resolve every cited exec_id against `audit/exec_log.jsonl` and
re-check whether the parsed output structurally supports the claim.

For cross-source claims, **multi-cite** all relevant exec_ids in the same
sentence: `[CONFIRMED] STUN.exe (PID 1912) connected to external IP 1.2.3.4
(vol3_psscan exec_id=…, vol3_netscan exec_id=…, vol3_cmdline exec_id=…)`.

Negative assertions are valid claims: `[CONFIRMED] No 1102 events on dc.evtx
(ezt_evtx_parse exec_id=…)` is acceptable and verifiable.

When you are done, print `BASELINE RUN COMPLETE` to stdout.
