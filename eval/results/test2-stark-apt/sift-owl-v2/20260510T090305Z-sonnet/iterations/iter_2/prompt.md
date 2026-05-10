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


## Iteration 1's final report (for reference; build on it)

<<<
Loading MCP tool schemas to begin the investigation.

Starting the investigation. Running `tsk_fls_list` on DC, nromanoff, and tdungan simultaneously to locate SYSTEM hives and EVTX files.

Now querying for SYSTEM hive and EVTX files on all three hosts in parallel.

Found SYSTEM hive inodes. Now querying for Security and System event logs on all three hosts, plus searching for malware artifacts.

All inodes found. Now extracting all critical artifacts in parallel — SYSTEM hives, $MFTs, and event logs from all three hosts.

All extractions complete. Now running EZ Tools parsing on all artifacts simultaneously — shimcache on all SYSTEM hives, MFT on all $MFTs, EVTX on all event logs.

**Extract IDs collected:**
- DC $MFT: `019e1122-d676`  |  DC SYSTEM: `019e1122-def3`  |  DC Security.evtx: `019e1122-e629`  |  DC System.evtx: `019e1122-e992`
- nromanoff $MFT: `019e1122-d9f9`  |  nromanoff SYSTEM: `019e1122-e245`  |  nromanoff Security.evtx: `019e1122-ea67`  |  nromanoff System.evtx: `019e1122-ed0a`
- tdungan $MFT: `019e1122-dc81`  |  tdungan SYSTEM: `019e1122-e329`  |  tdungan SecEvent.Evt: `019e1122-ee8a`  |  tdungan SysEvent.Evt: `019e1122-f1bb`

Shimcache and MFT parses returned. Critical findings so far:
- **nromanoff shimcache**: `spinlock.exe` (2012-04-03T22:53:39Z, Executed:Yes), `hydrakatz.exe` (2012-04-04T01:00:45Z, Executed:Yes), `a.exe` ~30 executions 2012-04-04T00:14–00:44Z, `PSEXESVC.EXE` (2012-04-04T01:46:37Z)
- **tdungan shimcache**: `spinlock.exe` (2012-04-04T17:06:37Z)
- tdungan XP event logs: 0 events — EvtxECmd cannot parse legacy .EVT format
- DC EVTX: connection errors — retrying now

Running parallel queries: shimcache drills for malware on DC, MFT searches for key artifacts, retrying DC event logs.

Excellent findings emerging. DC EVTX re-extracted successfully. Now parsing DC event logs and querying remaining MFT targets.

Key findings so far:
- **DC MFT**: `usboesrv.exe` in both `Program Files\USB over Ethernet\` AND `Windows\System32\` — created AFTER modified date (anti-forensic timestomping). `spinlock.exe` only as WER crash report. No `EXFIL.pst` or `hotcorewin2k.sys` in DC MFT.
- **nromanoff MFT**: `adberdr813.exe` in Downloads (2011-08-28, record_changed 2012-04-04), `spinlock.exe` in System32 + `vibranium` user Temp dirs (multiple manifest files), `hydrakatz.exe` in System32.
- **tdungan MFT**: `AdbeRdr910_en_US.exe` deleted from Dropbox cache (2012-04-02), `spinlock.exe` in system32, `vibranium` user Temp on tdungan too.

DC Security.evtx is 134MB — parsing is timing out. DC MFT reveals `vibranium` user profile created 2012-04-04T17:29Z on DC itself. `EXFIL.pst` found on **tdungan** not DC (vibranium's Outlook folder). `hotcorewin2k.sys` found timestomped on tdungan. Retrying DC System.evtx and nromanoff EVTX to get exec_ids for query_rows drilling.

DC System.evtx still timing out (134MB Security.evtx is definitely too large). The nromanoff Security EVTX parse is oversized — exec_id is stored in the output file but I cannot access it without the Read tool. Running final targeted queries.

I have gathered all available evidence. DC System.evtx and Security.evtx both timeout on every parse attempt (134MB file too large for MCP transport). Writing the final report now.

---

# STARK-APT-001 — Supplemental DFIR Report
## EZ Tools Analysis: MFT, ShimCache, Event Logs

**Case:** SANS FOR508 Stark Research Labs Data Breach  
**Analyst:** SIFT-OWL v2 / iter_1  
**Analysis Date:** 2026-05-10 UTC  
**Scope:** Gap-fill analysis via `ezt_mft_parse`, `ezt_shimcache_parse`, `ezt_evtx_parse`

---

## 1. Disk Image Verification

`ewf_info` was not re-run (already confirmed in prior iteration). The following extractions all matched prior SHA256 values on re-extraction, confirming image integrity. Images are logical-drive (single-volume, offset=null) captures.

---

## 2. GAP 1 — Run-key / Service Persistence Timestamps

### 2.1 usboesrv.exe — Domain Controller (DC)

**Two copies present in DC MFT** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab]:

| Path | Created | Modified | Flags |
|------|---------|----------|-------|
| `Program Files\USB over Ethernet\usboesrv.exe` | 2012-03-20T17:57:58Z | **2012-02-09T12:31:54Z** | usec_zeros, copied |
| `Windows\System32\usboesrv.exe` | 2012-03-20T17:57:59Z | 2012-03-20T17:57:59Z | clean |

The `Program Files` copy has a Modified timestamp that predates its own Created timestamp by 39 days — a definitive anti-forensic indicator (timestomping). The `System32` copy was dropped on 2012-03-20T17:57:59Z, one second after the original, and is the service binary registered for auto-start.

The `usboesrv.exe` binary is **absent from the DC ShimCache** (0 matches in 962 entries) [CONFIRMED — exec_id 019e1123-20c8-79e3-a814-7d52002b8c38]. This is consistent with Windows Server 2008 R2 behavior where service executables loaded via the Service Control Manager (`services.exe`) frequently bypass AppCompatCache registration.

[INFERRED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab; reasoning: Dual-copy pattern (original installation directory + System32) combined with 2012-03-20 creation timestamps and ShimCache absence is the canonical service-registration persistence pattern. The binary was deployed to DC weeks before the April 2012 active phase.]

**No `usboesrv.exe` was found in nromanoff or tdungan MFT** [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792; exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba — both returned 0 rows].

### 2.2 spinlock.exe — nromanoff

[CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792, exec_id 019e1123-26a3-7c51-be46-fad7c6993479]:

| Attribute | Value |
|-----------|-------|
| Path | `Windows\System32\spinlock.exe` |
| Created | 2012-04-03T22:59:43Z |
| **Modified** | **2012-04-03T22:53:39Z** ← Created AFTER Modified (timestomped) |
| Record Changed | 2012-04-03T23:02:30Z |
| File Size | 2,271,885 bytes |
| usec_zeros | true |
| copied | true |
| ShimCache position | 7 (8th most recent), Executed: Yes |
| ShimCache LastModified | 2012-04-03T22:53:39Z |
| Prefetch created | 2012-04-03T23:09:26Z |
| Prefetch last run | 2012-04-04T18:55:01Z |

Six `spinlock.exe.manifest` files (PyInstaller `_MEI*` temp dirs) under `Users\vibranium\AppData\Local\Temp\` span 2012-04-03T23:09:16Z → 2012-04-04T18:54:51Z, confirming the vibranium account ran spinlock at least six discrete times on nromanoff.

### 2.3 spinlock.exe — tdungan

[CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba, exec_id 019e1123-2b73-75a0-ad0a-37769fe4cd76]:

| Attribute | Value |
|-----------|-------|
| Path | `WINDOWS\system32\spinlock.exe` |
| Created | 2012-04-04T17:04:44Z |
| Modified | 2012-04-04T17:06:37Z (normal order) |
| File Size | 2,271,885 bytes — **identical to nromanoff copy** |
| ShimCache position | 0 (most recent), Executed: NA (XP) |
| ShimCache LastModified | 2012-04-04T17:06:37Z |
| Prefetch created | 2012-04-05T17:15:56Z |
| Prefetch last run | **2012-04-06T13:25:11Z** |

One `spinlock.exe.manifest` under `Documents and Settings\vibranium\Local Settings\Temp\_MEI122362\` created 2012-04-05T17:16:01Z confirms interactive vibranium execution on tdungan.

### 2.4 spinlock.exe — Domain Controller

**The spinlock.exe binary is absent from DC MFT** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, 0 matches on `file_name: spinlock.exe`]. A WER crash folder `NonCritical_spinlock.exe_f55bbffa...` was created 2012-04-04T18:28:42Z [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab], proving spinlock was executed on the DC and crashed, but the binary was subsequently deleted (likely sdelete). The absence from ShimCache is consistent with post-deletion shimcache gap.

[INFERRED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab; reasoning: WER crash folder without the binary or ShimCache entry = binary executed, crashed, then sdelete'd. The vibranium user profile on the DC (created 2012-04-04T17:29:33Z) provides the account context for the execution ~1 hour before the WER timestamp.]

---

## 3. GAP 2 — Execution Timestamps: a.exe, hydrakatz.exe, spinlock.exe

### 3.1 a.exe — nromanoff

[CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479, exec_id 019e1123-52f9-7f71-9651-69158614d792]:

ShimCache records **~30 separate executions** of `C:\Windows\TEMP\a.exe` from 2012-04-04T00:14:13Z to 2012-04-04T00:44:11Z, each entry with a unique `last_modified` timestamp approximately 1 minute apart. This is consistent with a.exe being regenerated (rewritten to disk) each run — a common technique for evading static file hashing.

MFT shows `Users\vibranium\AppData\Local\Temp\a.exe` (entry 420, seq 9): Created 2012-04-04T02:22:00Z, Modified 2012-04-07T17:34:10Z, file_size 9,216 bytes. This 9KB version post-dates the ShimCache executions, indicating an earlier version (in TEMP) was replaced with a smaller persistent version in the vibranium Temp directory.

**No a.exe was found in DC MFT TEMP paths** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, 0 relevant matches]; **not present in DC ShimCache TEMP entries** [CONFIRMED — exec_id 019e1123-20c8-79e3-a814-7d52002b8c38].

### 3.2 hydrakatz.exe — nromanoff

[CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479, exec_id 019e1123-52f9-7f71-9651-69158614d792]:

| Attribute | Value |
|-----------|-------|
| MFT path | `Windows\System32\hydrakatz.exe` |
| Created | 2012-04-04T01:00:07Z |
| Modified | 2012-04-04T01:00:45Z (normal order — not timestomped) |
| File Size | 548,848 bytes |
| ShimCache position | 14, Executed: Yes |
| ShimCache LastModified | 2012-04-04T01:00:45Z |
| Prefetch created | 2012-04-04T01:09:03Z |
| Prefetch last run | **2012-04-05T13:20:58Z** |

hydrakatz.exe is NOT in DC MFT or nromanoff file listing [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, 0 matches]. Credential harvesting was confined to nromanoff.

### 3.3 PSEXESVC.EXE — nromanoff (lateral movement indicator)

[CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479]:

`C:\Windows\PSEXESVC.EXE`, ShimCache position 9, LastModified 2012-04-04T01:46:37Z, Executed: Yes. PsExec drops its service binary (`PSEXESVC.EXE`) on the **target** machine. This confirms nromanoff was the target of an inbound PsExec operation around 2012-04-04T01:46Z, meaning the attacker used PsExec FROM another compromised host to execute commands on nromanoff.

---

## 4. GAP 3 — MFT Timestamps for Trojanized Installers and EXFIL.pst

### 4.1 adberdr813.exe — nromanoff

[CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792]:

| Attribute | Value |
|-----------|-------|
| Path | `Users\nromanoff\Downloads\adberdr813.exe` |
| MFT Entry | 48869, seq 2 |
| Created | 2011-08-28T22:33:18Z |
| Modified | 2011-08-28T22:35:24Z |
| **Record Changed** | **2012-04-04T15:21:06Z** (anomalous) |
| File Size | 21,806,256 bytes (21MB) |
| has_ads | true (Zone.Identifier confirmed — browser download) |
| Timestomped | false |

The Record Changed timestamp of 2012-04-04T15:21:06Z — over 8 months after the download — indicates the MFT record was accessed or modified during the active intrusion phase. This may reflect the attacker enumerating or touching the file.

A WER crash archive `AppCrash_adberdr813.exe_4e6f6a6fc187a212f1b1b22f543c633f36ebbe_0cd92e4e` was created 2011-08-28T22:35:45Z [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792], confirming execution and crash on the same day as the download — the exploit caused the Reader crash while dropping the payload.

ShimCache entry for `adberdr813.exe` shows LastModified 2011-08-28T22:35:24Z, **Executed: No** [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479]. The "No" flag is consistent with the binary crashing before the Windows program loader could register the shimcache execute flag — the WER crash report is the corroborating execution proof.

### 4.2 AdbeRdr910_en_US.exe — tdungan

[CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba]:

| Attribute | Value |
|-----------|-------|
| Path | `Documents and Settings\tdungan\My Documents\Dropbox\.dropbox.cache\2012-04-02\AdbeRdr910_en_US (deleted ...).exe` |
| Created | 2012-04-02T12:40:16Z |
| Modified | 2012-04-02T12:40:47Z |
| Record Changed | 2012-04-02T12:41:51Z |
| File Size | 26,739,584 bytes (26MB) |
| usec_zeros | true |
| Prefetch | `ADBERDR910_EN_US.EXE-2CFF2AE5.pf` created 2012-04-02T12:40:31Z |

The Prefetch file was created 15 seconds after the MFT Created timestamp, confirming execution. The `(deleted ...)` in the filename indicates Dropbox auto-cached the file when it was deleted from the Dropbox folder. The `usec_zeros` flag indicates this is the actual dropped malware (not an OS binary).

AdbeRdr910 is **absent from tdungan ShimCache** [CONFIRMED — exec_id 019e1123-2b73-75a0-ad0a-37769fe4cd76, 0 matches]. XP ShimCache capacity (96 entries per ControlSet) was likely exhausted; subsequent entries evicted it. The Prefetch file remains as the execution proof.

### 4.3 EXFIL.pst — tdungan

[CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba]:

**EXFIL.pst was found on tdungan, not the DC.**

| Attribute | Value |
|-----------|-------|
| Path | `Documents and Settings\vibranium\Local Settings\Application Data\Microsoft\Outlook\EXFIL.pst` |
| MFT Entry | 13043, seq 7 |
| Created | **2012-04-05T16:07:58Z** |
| Modified | **2012-04-05T16:11:13Z** (~3 min to populate) |
| Accessed | 2012-04-06T05:05:24Z |
| File Size | 16,778,240 bytes (16MB) |
| In Use | true (not deleted) |
| Timestomped | false |

The 3-minute window between creation and modification (16:07 → 16:11) is consistent with a scripted PST-building operation. Vibranium's browser temp folder (`Content.IE5\O52ZG5AZ`) was last modified 2012-04-05T16:11:20Z [CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba], seven seconds after PST completion, suggesting a browser-based web upload was the exfiltration method.

**EXFIL.pst was NOT found in DC MFT** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, 0 matches]. **EXFIL.pst was NOT found in nromanoff MFT** [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792, 0 matches].

---

## 5. GAP 4 — Authentication / Lateral Movement

### 5.1 vibranium Account — Multi-Host Profile Evidence

[CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792, exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba, exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab]:

The vibranium account profile directories exist on all three compromised hosts:

| Host | Profile Created | First Tool Activity | NTUSER.DAT Last Modified |
|------|----------------|---------------------|--------------------------|
| nromanoff | (spinlock Temp dir) 2012-04-03T23:09:16Z | spinlock 2012-04-03T22:59Z | — |
| tdungan | 2012-04-04T16:40:20Z | spinlock 2012-04-04T17:04Z | 2012-04-06T18:58:29Z |
| DC | 2012-04-04T17:29:33Z | (spinlock crash) 2012-04-04T18:28Z | 2012-04-08T16:59:43Z |

The chronological order (nromanoff → tdungan → DC) indicates nromanoff was the lateral movement origin.

### 5.2 PsExec Lateral Movement — nromanoff

[CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479]:

PSEXESVC.EXE present on nromanoff shimcache (position 9, Executed:Yes, LastModified 2012-04-04T01:46:37Z). nromanoff was the **target** of an inbound PsExec execution, originating from a host that already had the vibranium account active.

### 5.3 DC Event Log — GAP

[GAP]: The DC Security.evtx (134,221,824 bytes) failed to parse on all four attempts due to MCP transport timeout (connection closed). The DC System.evtx (7,409,664 bytes) similarly failed. Cannot confirm EID 4720 (vibranium account creation), EID 4769 (Kerberos ticket), EID 7045 (service install), or EID 1102 (log clear) from direct event log evidence. Resolving this gap would require direct host-side `EvtxECmd` execution with output piped to CSV, bypassing MCP transport limits.

### 5.4 nromanoff Security.evtx — Partial Gap

The nromanoff Security.evtx (4,198,400 bytes) was parsed successfully both times, but the 3,096,810-character JSON output exceeds MCP transport limits and was written to a local file. The `exec_id` for this parse is embedded in that file but is not accessible without the `Read` tool (denied in this session). ShimCache and MFT data above provide equivalent execution evidence. The by_event_id schema header confirms events 4624, 4625, 4634, 4647, 4648, 4663, 4672 are present in the log.

### 5.5 tdungan Event Logs — Parsing Failure

[CONFIRMED — exec_id 019e1124-5e07-71c1-8f43-4c35ed87f968; exec_id 019e1124-60e3-78c2-83e9-31d9c7732c3c]: Both `SecEvent.Evt` and `SysEvent.Evt` on tdungan returned 0 events. EvtxECmd does not support the legacy Win XP `.EVT` binary format; it requires Vista+ `.evtx`. Tdungan event log data is inaccessible via this tool path. An alternative would be to use `evtxtract` or `log2timeline` with the `winevt` parser on the raw `.Evt` files.

---

## 6. GAP 5 — Service Installs (7045 Events)

[GAP]: DC System.evtx parse failed (see §5.3). Cannot confirm EID 7045 for `usboesrv` or any service installed by the attacker on the DC via direct log evidence.

[CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab]: DC MFT shows `usboesrv.exe` placed in `Windows\System32\` on 2012-03-20T17:57:59Z. The dual-directory deployment pattern (Program Files + System32), combined with the prior run's memory analysis confirming `usboesrv.exe` was a running process with active C2 connection to `96.255.98.154:29932`, constitutes confirmation of service installation even absent EID 7045.

---

## 7. Additional Finding — hotcorewin2k.sys (Kernel Driver) on tdungan

[CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba]:

**hotcorewin2k.sys was found on tdungan in multiple locations:**

| Path | Created | Modified | Flags |
|------|---------|----------|-------|
| `Documents and Settings\tdungan\Local Settings\Temp\hotcore2K\hotcorewin2k.sys` | **2011-05-17T22:56:56Z** | **2011-05-17T22:56:56Z** | **Timestomped:true, usec_zeros:true** |
| `WINDOWS\system32\DRVSTORE\hotcorewin_467876402388C48D68EC19B30C952B93BB4C65F0\hotcorewin2k.sys` | 2012-03-21T03:17:51Z | **2011-05-17T22:56:56Z** | usec_zeros:true, copied:true |

The Temp copy was timestomped to appear as a 2011-05-17 artifact. The Driver Store record_changed timestamp of 2012-03-21T03:14:07Z reveals the actual driver installation time. The Temp copy was last accessed 2012-04-05T05:36:37Z.

**hotcorewin2k.sys is absent from nromanoff MFT** [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792, 0 matches] and **absent from DC MFT** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, 0 matches].

---

## 8. DC ShimCache — No Attacker Tools Present

[CONFIRMED — exec_id 019e1123-20c8-79e3-a814-7d52002b8c38]:

All searches for attacker tools in the DC ShimCache (962 entries) returned 0 matches:
- `spinlock` → 0 rows
- `usboesrv` / `usbo` → 0 rows
- `hydrakatz` → 0 rows
- `a.exe` (TEMP) → 0 rows (only legitimate OS binaries matched)

The DC ShimCache contains only legitimate binaries. This is consistent with: (a) usboesrv running as a service (bypasses ShimCache); (b) spinlock being sdelete'd after crashing; (c) the DC being used as a pivot point for tool deployment to other hosts rather than tool execution on the DC itself.

---

## 9. Consolidated Timeline (New Evidence)

| Time (UTC) | Host | Event | Evidence Source |
|-----------|------|-------|----------------|
| 2011-08-28T22:33Z | nromanoff | `adberdr813.exe` downloaded (21MB) | MFT exec_id 019e1123-52f9 |
| 2011-08-28T22:35Z | nromanoff | `adberdr813.exe` executed; Adobe Reader crashed; payload dropped | WER MFT exec_id 019e1123-52f9; ShimCache exec_id 019e1123-26a3 |
| 2012-03-20T17:57Z | DC | `usboesrv.exe` deployed to System32 and Program Files\USB over Ethernet | MFT exec_id 019e1123-2e48 |
| 2012-03-21T03:14Z | tdungan | `hotcorewin2k.sys` installed (driver store record_changed) | MFT exec_id 019e1123-6e98 |
| 2012-04-02T12:40Z | tdungan | `AdbeRdr910_en_US.exe` executed (Dropbox delivery); Prefetch created | MFT exec_id 019e1123-6e98 |
| 2012-04-03T22:53Z | nromanoff | `spinlock.exe` dropped (file modified time; timestomped) | ShimCache exec_id 019e1123-26a3; MFT exec_id 019e1123-52f9 |
| 2012-04-03T23:09Z | nromanoff | spinlock first run under vibranium account (MEI manifest) | MFT exec_id 019e1123-52f9 |
| 2012-04-04T00:14–00:44Z | nromanoff | `a.exe` run ~30 times (ShimCache, ~1 min intervals) | ShimCache exec_id 019e1123-26a3 |
| 2012-04-04T01:00Z | nromanoff | `hydrakatz.exe` dropped + executed (credential harvest) | ShimCache exec_id 019e1123-26a3; MFT exec_id 019e1123-52f9 |
| 2012-04-04T01:46Z | nromanoff | PSEXESVC.EXE dropped (PsExec FROM external host TO nromanoff) | ShimCache exec_id 019e1123-26a3 |
| 2012-04-04T16:40Z | tdungan | vibranium profile created (first interactive logon) | MFT exec_id 019e1123-6e98 |
| 2012-04-04T17:04Z | tdungan | `spinlock.exe` dropped | MFT exec_id 019e1123-6e98 |
| 2012-04-04T17:29Z | DC | vibranium profile created (first interactive logon) | MFT exec_id 019e1123-2e48 |
| 2012-04-04T18:28Z | DC | spinlock crashes on DC → WER report; binary subsequently deleted | MFT exec_id 019e1123-2e48 |
| 2012-04-05T16:07–16:11Z | tdungan | `EXFIL.pst` created (16MB) under vibranium's Outlook | MFT exec_id 019e1123-6e98 |
| 2012-04-05T16:11Z | tdungan | Browser temp (`Content.IE5`) modified (web exfil likely) | MFT exec_id 019e1123-6e98 |
| 2012-04-05T17:16Z | tdungan | spinlock run again via vibranium | MFT exec_id 019e1123-6e98 |
| 2012-04-06T13:25Z | tdungan | spinlock.exe last run (Prefetch last modified) | MFT exec_id 019e1123-6e98 |
| 2012-04-06T18:58Z | tdungan | vibranium NTUSER.DAT last modified (last activity) | MFT exec_id 019e1123-6e98 |
| 2012-04-07T17:34Z | nromanoff | `a.exe` (vibranium Temp) last modified | MFT exec_id 019e1123-52f9 |
| 2012-04-08T16:59Z | DC | vibranium NTUSER.DAT last modified (last DC activity) | MFT exec_id 019e1123-2e48 |

---

## 10. Remaining Gaps

| Gap | What's Missing | How to Resolve |
|-----|---------------|----------------|
| DC Security.evtx (134MB) | EID 4720 vibranium creation, EID 4769 Kerberos, EID 1102 log clear | Run `EvtxECmd` directly on host with CSV output piped locally; avoid MCP 3MB transport limit |
| DC System.evtx (7.4MB) | EID 7045 service install for usboesrv, spinlock | Same as above |
| nromanoff Security.evtx exec_id | EID 4624 logons, 4688 process creates; parse result oversized (3MB) | Use Read tool to retrieve exec_id from saved result file; then query_rows for specific event IDs |
| tdungan SecEvent.Evt / SysEvent.Evt | EvtxECmd cannot parse XP .EVT format (0 events returned) | Use `evtxtract` or `log2timeline --parsers winevt` on the raw .Evt files |
| Run-key registry values | Specific HKLM\SOFTWARE Run keys or Service keys for usboesrv/spinlock persistence | Extract DC SOFTWARE hive (inode lookup needed); parse with RegHive tool |
| nromanoff / tdungan usboesrv | Tool absent from both; only on DC | No further investigation needed — host scope confirmed |

---

## 11. Summary of New Confirmed Findings

1. **adberdr813.exe initial compromise timestamp confirmed as 2011-08-28T22:33Z** on nromanoff — WER crash and ShimCache both corroborate execution; "Executed:No" in ShimCache explained by crash before flag write. [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792, exec_id 019e1123-26a3-7c51-be46-fad7c6993479]

2. **usboesrv.exe deployed to DC on 2012-03-20** with anti-forensic timestomping on the Program Files copy. Two copies confirm service-registration persistence pattern. Absent from shimcache (service loader bypass). [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, exec_id 019e1123-20c8-79e3-a814-7d52002b8c38]

3. **spinlock.exe timestomped on nromanoff** (Created > Modified by 6 minutes), usec_zeros:true, copied:true — anti-forensic flags confirmed. Identical 2,271,885-byte binary on both nromanoff and tdungan. [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792, exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba]

4. **a.exe ran ~30 times in 30 minutes** on nromanoff (00:14–00:44Z on 2012-04-04) with file being regenerated each cycle — indicative of automated credential spraying or callback loop. [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479]

5. **hydrakatz.exe** confirmed on nromanoff; last run 2012-04-05T13:20:58Z via Prefetch. Not present on DC or tdungan. [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479, exec_id 019e1123-52f9-7f71-9651-69158614d792]

6. **EXFIL.pst is on tdungan** (not DC) under the vibranium Outlook profile, created 2012-04-05T16:07–16:11Z; 16MB, live on disk, likely exfiltrated via browser. [CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba]

7. **hotcorewin2k.sys timestomped on tdungan** to appear as a 2011-05-17 file; actual installation 2012-03-21T03:14Z. Absent from DC and nromanoff. [CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba]

8. **vibranium account present on all three hosts** with first activity: nromanoff (2012-04-03T23:09Z) → tdungan (2012-04-04T16:40Z) → DC (2012-04-04T17:29Z) — confirming nromanoff was the lateral movement origin. [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792, exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba, exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab]

9. **PsExec used against nromanoff** — PSEXESVC.EXE on nromanoff ShimCache (2012-04-04T01:46Z) confirms nromanoff was a PsExec target from another compromised host. [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479]

10. **No attacker tools in DC ShimCache** — DC was used as a persistence/pivot platform (service-level, not interactive tool execution) until the vibranium account was activated on 2012-04-04T17:29Z. [CONFIRMED — exec_id 019e1123-20c8-79e3-a814-7d52002b8c38]

---

SIFT-OWL RUN COMPLETE
>>>


---

## Validator feedback from iteration 1

The following CONFIRMED claims from your previous iteration's report were
DEMOTED by the rule-based validator. The validator checks whether every
testable token (PIDs, IPs, filenames, paths, timestamps, hashes) in a
CONFIRMED claim is structurally present in the parsed JSON of the cited
`exec_id`. Demoted statuses:

- **partial** — some tokens matched, some missing. Multi-source paragraph
  cites only one tool? Use multi-cite syntax `[CONFIRMED — exec_id A, exec_id B]`.
- **failed** — no tokens matched, OR a negated assertion was contradicted by
  the evidence. Re-check the claim against the cited tool's data.
- **not_confirmed** — `[CONFIRMED]` tag found without an `exec_id` citation.
  Cite explicitly per-claim, not "[All exec_id …]" once at the bottom.

You have full access to the shared audit log via `query_rows(exec_id, ...)` —
all exec_ids from your previous iteration are still reachable. Drill into
them to confirm or refute each flagged claim.

For EACH flagged claim below, you must do exactly one of:

  1. **Re-confirm with multi-cite**: keep the [CONFIRMED] tag and add the
     missing exec_ids: `[CONFIRMED — exec_id A, exec_id B]`. Use this when
     you can locate supporting evidence in another tool's data.
  2. **Demote to [INFERRED]**: if the claim is your reasoning derived from
     evidence, change the tag and add reasoning: `[INFERRED — exec_id A;
     reasoning: …]`.
  3. **Demote to [GAP]**: if the evidence to confirm just isn't available
     to you, mark it `[GAP — would need: …]`.

DO NOT remove flagged claims silently. Every flagged claim must appear
explicitly in your iteration 2 report with one of the three resolutions
above. Otherwise treat the prior report as a starting point — keep
verified claims as-is, and add any new evidence you discover.

### Demotion list — 11 claims

**[1] partial** — cited tool(s): ezt_mft_parse — exec_ids: (none)
- missing tokens (claim says X but X not in cited tool's data): `NonCritical_spinlock.exe_f55bbffa...`, `file_name: spinlock.exe`
- negation violations (claim says NOT X but X IS in cited tool's data): `spinlock.exe`
- already matched: `2012-04-04T18:28:42Z`
> **The spinlock.exe binary is absent from DC MFT** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, 0 matches on `file_name: spinlock.exe`]. A WER crash folder `NonCritical_spinlock.exe_f55bbffa...` was created 2012-04-04T18:28:42Z [CONFIRMED — exec_id 019e1123-2e48-7b90…


**[2] partial** — cited tool(s): ezt_mft_parse — exec_ids: (none)
- missing tokens (claim says X but X not in cited tool's data): `NonCritical_spinlock.exe_f55bbffa...`, `file_name: spinlock.exe`
- negation violations (claim says NOT X but X IS in cited tool's data): `spinlock.exe`
- already matched: `2012-04-04T18:28:42Z`
> **The spinlock.exe binary is absent from DC MFT** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, 0 matches on `file_name: spinlock.exe`]. A WER crash folder `NonCritical_spinlock.exe_f55bbffa...` was created 2012-04-04T18:28:42Z [CONFIRMED — exec_id 019e1123-2e48-7b90…


**[3] failed** — cited tool(s): ezt_mft_parse — exec_ids: (none)
- negation violations (claim says NOT X but X IS in cited tool's data): `a.exe`
> **No a.exe was found in DC MFT TEMP paths** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, 0 relevant matches]; **not present in DC ShimCache TEMP entries** [CONFIRMED — exec_id 019e1123-20c8-79e3-a814-7d52002b8c38].


**[4] failed** — cited tool(s): ezt_shimcache_parse — exec_ids: (none)
- negation violations (claim says NOT X but X IS in cited tool's data): `a.exe`
> **No a.exe was found in DC MFT TEMP paths** [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab, 0 relevant matches]; **not present in DC ShimCache TEMP entries** [CONFIRMED — exec_id 019e1123-20c8-79e3-a814-7d52002b8c38].


**[5] partial** — cited tool(s): ezt_evtx_parse, ezt_evtx_parse — exec_ids: (none)
- missing tokens (claim says X but X not in cited tool's data): `log2timeline`, `evtxtract`, `.evtx`, `winevt`, `SecEvent.Evt`, `SysEvent.Evt`
> [CONFIRMED — exec_id 019e1124-5e07-71c1-8f43-4c35ed87f968; exec_id 019e1124-60e3-78c2-83e9-31d9c7732c3c]: Both `SecEvent.Evt` and `SysEvent.Evt` on tdungan returned 0 events. EvtxECmd does not support the legacy Win XP `.EVT` binary format; it requires Vista+ `.evtx`. Tdungan eve…


**[6] partial** — cited tool(s): ezt_mft_parse — exec_ids: (none)
- negation violations (claim says NOT X but X IS in cited tool's data): `usboesrv.exe`
- already matched: `2012-03-20T17:57:59Z`, `Windows\System32\`
> [CONFIRMED — exec_id 019e1123-2e48-7b90-bcaa-315b2cefc7ab]: DC MFT shows `usboesrv.exe` placed in `Windows\System32\` on 2012-03-20T17:57:59Z. The dual-directory deployment pattern (Program Files + System32), combined with the prior run's memory analysis confirming `usboesrv.exe`…


**[7] partial** — cited tool(s): ezt_mft_parse, ezt_shimcache_parse — exec_ids: (none)
- missing tokens (claim says X but X not in cited tool's data): `2011-08-28T22:33Z`
- already matched: `adberdr813.exe`
> 1. **adberdr813.exe initial compromise timestamp confirmed as 2011-08-28T22:33Z** on nromanoff — WER crash and ShimCache both corroborate execution; "Executed:No" in ShimCache explained by crash before flag write. [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792, exec_id…


**[8] failed** — cited tool(s): ezt_mft_parse — exec_ids: (none)
- negation violations (claim says NOT X but X IS in cited tool's data): `2012-04-05T16:07`, `EXFIL.pst`
> 6. **EXFIL.pst is on tdungan** (not DC) under the vibranium Outlook profile, created 2012-04-05T16:07–16:11Z; 16MB, live on disk, likely exfiltrated via browser. [CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba]


**[9] partial** — cited tool(s): ezt_mft_parse — exec_ids: (none)
- missing tokens (claim says X but X not in cited tool's data): `2012-03-21T03:14Z`
- already matched: `hotcorewin2k.sys`
> 7. **hotcorewin2k.sys timestomped on tdungan** to appear as a 2011-05-17 file; actual installation 2012-03-21T03:14Z. Absent from DC and nromanoff. [CONFIRMED — exec_id 019e1123-6e98-7141-b6f1-225a1ef51bba]


**[10] failed** — cited tool(s): ezt_mft_parse, ezt_mft_parse, ezt_mft_parse — exec_ids: (none)
- missing tokens (claim says X but X not in cited tool's data): `2012-04-04T17:29Z`, `2012-04-03T23:09Z`, `2012-04-04T16:40Z`
> 8. **vibranium account present on all three hosts** with first activity: nromanoff (2012-04-03T23:09Z) → tdungan (2012-04-04T16:40Z) → DC (2012-04-04T17:29Z) — confirming nromanoff was the lateral movement origin. [CONFIRMED — exec_id 019e1123-52f9-7f71-9651-69158614d792, exec_id…


**[11] partial** — cited tool(s): ezt_shimcache_parse — exec_ids: (none)
- missing tokens (claim says X but X not in cited tool's data): `2012-04-04T01:46Z`
- already matched: `PSEXESVC.EXE`
> 9. **PsExec used against nromanoff** — PSEXESVC.EXE on nromanoff ShimCache (2012-04-04T01:46Z) confirms nromanoff was a PsExec target from another compromised host. [CONFIRMED — exec_id 019e1123-26a3-7c51-be46-fad7c6993479]



---

When you produce iteration 2's report, end with the line `SIFT-OWL RUN COMPLETE`.
