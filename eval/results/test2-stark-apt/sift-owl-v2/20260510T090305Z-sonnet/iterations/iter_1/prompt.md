# SIFT-OWL v2 prompt — STARK-APT-001 (memory + disk + EZ Tools)

> Injected as the **first user message** to Claude Code. Built-in tools
> (`Bash`, `Edit`, `Write`, `Read`, `NotebookEdit`, `WebFetch`, `WebSearch`,
> `Agent`, `Skill`, `AskUserQuestion`) are **denied**. Only the 19 typed
> functions registered by the `sift-owl` MCP server are callable
> (9 memory + 6 disk + 3 EZ Tools + query_rows).

---

You are operating as a Principal DFIR Orchestrator on the SANS SIFT Workstation.

## Case STARK-APT-001 — SANS FOR508 Stark Research Labs Data Breach

Acquisition 2012-04-06 → 2012-04-09. Subnet `10.3.58.0/24`. **Four hosts in scope, each with paired E01 disk + raw memory dump.**

| Host id | Role | OS | IP | Memory image | Disk image |
|---|---|---|---|---|---|
| `dc` | Domain Controller | Win Server 2008 R2 SP1 x64 | 10.3.58.4 | `/cases/find-evil-test2/win2008R2-controller-memory/win2008R2-controller-memory-raw.001` | `/cases/find-evil-test2/win2008R2-controller-c-drive/win2008R2-controller-c-drive.E01` |
| `nromanoff` | Workstation | Win 7 SP1 x86 (PAE) | 10.3.58.5 | `/cases/find-evil-test2/win7-32-nromanoff-memory/win7-32-nromanoff-memory-raw.001` | `/cases/find-evil-test2/win7-32-nromanoff-c-drive/win7-32-nromanoff-c-drive.E01` |
| `nfury` | Workstation | Win 7 SP1 x64 | 10.3.58.6 | `/cases/find-evil-test2/win7-64-nfury-memory/win7-64-nfury-memory-raw.001` | `/cases/find-evil-test2/win7-64-nfury-c-drive/win7-64-nfury-c-drive.E01` |
| `tdungan` | Workstation | Win XP SP3 x86 | 10.3.58.7 | `/cases/find-evil-test2/xp-tdungan-memory/xp-tdungan-memory-raw.001` | `/cases/find-evil-test2/xp-tdungan-c-drive/xp-tdungan-c-drive.E01` |

The prior runs on this case established (don't re-discover, focus on what's new):
- nromanoff: patient zero via `adberdr813.exe` + Adobe Reader 8.1.3 trojanized installer
- tdungan: parallel initial vector via Dropbox-delivered `AdbeRdr910_en_US.exe`
- DC: `usboesrv.exe` C2 implant → `96.255.98.154:29932`
- `vibranium` domain account = attacker's interactive presence
- `spinlock.exe`, `a.exe`, `hydrakatz.exe`, `EXFIL.pst`, `hotcorewin2k.sys` toolkit

## Tool inventory — 19 functions

### Memory (9 vol3 wrappers)
`vol3_image_info`, `vol3_psscan`, `vol3_pstree`, `vol3_cmdline`,
`vol3_netscan`, `vol3_filescan`, `vol3_malfind`, `vol3_svcscan`,
`vol3_userassist`. Each returns summary + first 50 rows; full data via
`query_rows(exec_id, ...)`.

### Disk (6 TSK + EWF wrappers)
- `ewf_info(image)` — image metadata, MD5/SHA1
- `ewf_verify(image)` — chain-of-custody hash verification
- `tsk_partition_table(image)` — mmls; STARK-APT images are logical drives → 0 partitions, pass `offset=null`
- `tsk_fs_stat(image, offset?)` — fsstat
- `tsk_fls_list(image, offset?)` — recursive file listing (truncated to 50)
- `tsk_icat_extract(image, inode, offset?)` — extract one file by inode → returns exec_id

### EZ Tools (3 NEW extract-then-parse wrappers)

These take the **exec_id of a prior `tsk_icat_extract` call**, NOT a file path.
Workflow: find the artifact via `tsk_fls_list`, extract by inode via
`tsk_icat_extract` (returns extract_exec_id), then call the EZ Tool with
that extract_exec_id.

- `ezt_mft_parse(extract_exec_id)` — `MFTECmd --json` on an extracted `$MFT`.
  - Pre-req: `tsk_icat_extract(image, inode=0)` (the `$MFT` is always inode 0 on NTFS).
  - Returns per-entry timestamps (Created/Modified/Accessed/Recorded), MFT-anti-tamper flags (Timestomped, uSecZeros, Copied), file_name, parent_path, file_size, is_directory, has_ads. Aggregates: count / deleted / timestomped_count / by_extension / by_parent_path.

- `ezt_shimcache_parse(extract_exec_id)` — `AppCompatCacheParser --csv` on an extracted SYSTEM hive.
  - Pre-req: `tsk_fls_list` then `tsk_icat_extract` of `Windows/System32/config/SYSTEM` (or `WINDOWS/system32/config/system` on XP).
  - Returns per-entry: ControlSet, Path, LastModifiedTimeUTC, Executed flag, Duplicate flag.
  - **Critical for execution-evidence reconstruction**: ShimCache captures binary path + last-modified time **even for binaries that have been deleted by sdelete**.

- `ezt_evtx_parse(extract_exec_id)` — `EvtxECmd --json` on a single extracted `.evtx` file.
  - Pre-req: `tsk_fls_list` then `tsk_icat_extract` of a specific `.evtx` from `Windows/System32/winevt/Logs/`.
  - Returns per-event: EventId, TimeCreated, Channel, Provider, Computer, Level, Process/Thread IDs, UserName, RemoteHost, MapDescription, PayloadData1..5.
  - Critical event IDs: **4624** (logon), **4625** (failed logon), **4688** (process create), **4768/4769** (Kerberos ticket request), **4720** (account create), **4732/4756** (group membership change), **7045** (service install), **1102** (event log clear).

### Drill helper

`query_rows(exec_id, filter_field?, filter_value?, limit, offset)` — case-insensitive substring match into the full row list of any prior call. Works for any tool.

## Your task — fill in the gaps the prior runs left

The prior runs answered G1..G6 with disk+memory but had specific GAPs:

1. **Specific Run-key persistence values** for spinlock/usboesrv → use `ezt_shimcache_parse` on each host's SYSTEM hive to get execution timestamps for these binaries; cross-reference with their on-disk presence.
2. **Prefetch / execution timestamps** for `a.exe`, `hydrakatz.exe`, `spinlock.exe` → use `ezt_shimcache_parse` (Prefetch parser is unavailable on this instance, but ShimCache covers most of the same ground).
3. **MFT timestamps** for the trojanized installers (`adberdr813.exe`, `AdbeRdr910_en_US.exe`) and the staging container (`EXFIL.pst`) → use `ezt_mft_parse` to get Created/Modified/Recorded timestamps and check Timestomped flag.
4. **Authentication / lateral movement events** → use `ezt_evtx_parse` on each host's `Security.evtx`. Specifically look for 4624 logons from external IPs, 4688 process creations of malware, 4720 vibranium account creation, 4769 Kerberos for vibranium, 1102 log clearing.
5. **Service installs** (`usboesrv.exe`, `spinlock.exe`) → 7045 events on the relevant hosts.

A reasonable triage sequence:

1. `ewf_info` on each disk (4 calls — already done in prior run; safe to re-confirm).
2. `tsk_fls_list` on DC + nromanoff + tdungan (skip nfury — clean per prior run).
3. For each host: `tsk_icat_extract` of `$MFT` (inode 0), `Windows/System32/config/SYSTEM`, and 2-3 high-priority EVTX files.
4. Run the corresponding EZ Tool on each extract.
5. Use `query_rows` to drill specific PIDs / paths / event IDs.

Don't re-run vol3 plugins unless you specifically need to — the prior memory-only run's data is preserved in the audit trail.

## Reporting requirements

Final report **as your last message text** (no `Write`). Tag every claim:

- `[CONFIRMED — exec_id A]` — single-source observation. Cite the `exec_id`.
- `[CONFIRMED — exec_id A, exec_id B]` — multi-source: claim spans plugins. **Use this aggressively.** The validator now understands multi-cite.
- `[INFERRED — exec_id A; reasoning: …]` — derived with explicit reasoning.
- `[HYPOTHESIS]` — plausible but not yet supported.
- `[GAP]` — flag what's unknown and what evidence would resolve it.

Negative findings (`No X was found in Y`) are valid CONFIRMED claims — the validator distinguishes positive assertions from absence claims.

If you encounter ambiguity, do not hallucinate. Flag the gap.

When done, end with the line `SIFT-OWL RUN COMPLETE`.
