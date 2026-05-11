# SIFT-OWL v2 prompt — STARK-APT-001 (memory + disk + EZT + threat hunt)

> Injected as the **first user message** to Claude Code. Built-in tools
> (`Bash`, `Edit`, `Write`, `Read`, `NotebookEdit`, `WebFetch`, `WebSearch`,
> `Agent`, `Skill`, `AskUserQuestion`) are **denied**. Only the 38 typed
> functions registered by the `sift-owl` MCP server are callable.

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

Note: Vol3 cannot get PDB symbols for the nromanoff Win7-x86 PAE memory image (`ntkrpamp.pdb` is not auto-downloadable). Tag those memory queries with `[GAP]` and proceed via disk-side analysis for that host.

The prior runs on this case established (don't re-discover, focus on what's new + what the new tools reveal):
- **nromanoff** — patient zero via `adberdr813.exe` (trojanized Adobe Reader 8.1.3 installer); memory analysis blocked by missing PDB
- **tdungan** — parallel initial vector via Dropbox-delivered `AdbeRdr910_en_US.exe`
- **DC** — `usboesrv.exe` C2 implant → `96.255.98.154:29932`
- **`vibranium`** domain account = attacker's interactive presence
- Implant toolkit observed: `spinlock.exe` (email harvester), `a.exe` (HTTPPUMP), `hydrakatz.exe`, `EXFIL.pst` (staging container), `hotcorewin2k.sys` (kernel driver)

## Tool inventory — 38 typed read-only functions

### Memory (17 vol3 wrappers)
- Process: `vol3_image_info`, `vol3_psscan`, `vol3_pstree`, `vol3_cmdline`
- Network + files + injection: `vol3_netscan`, `vol3_filescan`, `vol3_malfind`
- Services + autostart: `vol3_svcscan`, `vol3_userassist`, `vol3_scheduled_tasks`
- Process internals: `vol3_dlllist(image, pid?)`, `vol3_handles(image, pid)`, `vol3_envars(image, pid?)`
- Credentials: `vol3_hashdump`, `vol3_cachedump`, `vol3_skeleton_key_check`
- Memory YARA: `vol3_vadyarascan(image, pid, ruleset_path?)`

### Disk (6 TSK + EWF)
`ewf_info`, `ewf_verify`, `tsk_partition_table(image)`, `tsk_fs_stat(image, offset?)`, `tsk_fls_list(image, offset?)`, `tsk_icat_extract(image, inode, offset?)` → returns `extract_exec_id`.

STARK-APT images are logical drives → `tsk_partition_table` returns 0 partitions; pass `offset=null` to fsstat/fls/icat.

### Windows artifacts via EZ Tools (10 extract-then-parse)
Each takes the **`extract_exec_id` of a prior `tsk_icat_extract`** — never a raw path.

- `ezt_mft_parse` — `MFTECmd --json` on `$MFT` (inode 0)
- `ezt_shimcache_parse` — AppCompatCacheParser on extracted SYSTEM hive
- `ezt_amcache_parse` — AmcacheParser on `Amcache.hve` (Win8.1+; not present on Win7/XP STARK-APT hosts)
- `ezt_evtx_parse` — EvtxECmd on a single `.evtx`. Critical IDs: 4624/4625/4688/4720/4732/4756/4768/4769/7045/1102.
- `ezt_prefetch_parse` — PECmd on a `.pf` file. Win10+ but Win7 also has Prefetch (XP has limited Prefetch).
- `ezt_jumplist_parse` — JLECmd on a `.automaticDestinations-ms` (Win7+; not on XP).
- `ezt_recyclebin_parse` — RBCmd on `$I*` (Win10) or `INFO2` (XP).
- `ezt_srum_parse` — SrumECmd on `SRUDB.dat` (Win8+ only — N/A for STARK-APT).
- `ezt_task_xml_parse` — Python parser for `\Windows\System32\Tasks\<name>` XMLs.
- `ezt_persistence_keys_parse` — RECmd with curated batch (Run/RunOnce/Winlogon/IFEO/AppInit/Services) on extracted SOFTWARE / NTUSER / SYSTEM hive.

### Threat hunt + carving + hashing (4)
- `yara_scan_extract(extract_exec_id, ruleset_path?)` — file-level YARA. Bundled rules cover Mimikatz residue, Cobalt Strike beacons, PowerShell encoded loaders, webshells (ASPX + PHP), PyInstaller packing, LSASS-dump magic, common RAS software.
- `bulk_extract(image)` — multi-scanner feature extraction: URLs, emails, IPs, domains, PE/ZIP/RAR signatures, EXIF, GPS, phones. Crucial when filesystem entries are missing but bytes remain (deleted archives, pagefile fragments).
- `strings_extract(extract_exec_id, min_length=6, encoding="all")` — bstrings on an extracted blob. Hardcoded URLs, mutex names, anti-sandbox checks, PDB paths.
- `hash_file(extract_exec_id)` — MD5/SHA-1/SHA-256/ssdeep on extracted bytes. IOC matching anchor.

### Drill helper
`query_rows(exec_id, filter_field?, filter_value?, limit, offset)` — case-insensitive substring match into any prior call's full row list.

## What this re-investigation should add

The prior STARK-APT v2 loop established the high-level chain at 86.1%
strict-verified. The agent's gaps then were:

1. **Disk-side persistence anchors** — Run keys, services, scheduled tasks
   were inferred from ShimCache + EVTX, not parsed directly from registry
   hives. With `ezt_persistence_keys_parse` + `ezt_task_xml_parse`, surface
   the actual Run/RunOnce/Services/Winlogon/IFEO values containing the
   implant paths.
2. **Credential dumps** — `vol3_handles(pid=lsass)` showed handle activity
   but the agent never confirmed actual hash extraction. Run `vol3_hashdump`
   and `vol3_cachedump` on the DC + Win7 hosts to either confirm or refute
   credential theft.
3. **Memory YARA on implants** — `p.exe`/`spinlock.exe`/`usboesrv.exe` were
   identified by name. Run `vol3_vadyarascan` against the specific PIDs to
   ground attribution claims in signature hits (Mimikatz / PyInstaller /
   Cobalt Strike rules).
4. **Strings on extracted implants** — `tsk_icat_extract` + `strings_extract`
   on `spinlock.exe`, `usboesrv.exe`, `a.exe` for hardcoded C2 indicators,
   mutex names, anti-sandbox checks. Pair with `hash_file` for IOC anchors.
5. **`bulk_extract` on the DC memory image** — Search the entire image for
   the C2 IP `96.255.98.154` and any related domains in pagefile / kernel
   pool fragments. Surfaces lateral / DNS activity below the netscan layer.
6. **`vol3_scheduled_tasks`** on DC + each Win7 host — Show the actual
   task entries (vs. inferring from EVTX 4688 process create events).
7. **Persistence via Run keys** — Extract `Windows\System32\config\SOFTWARE`
   on each host, run `ezt_persistence_keys_parse`. Should produce Run-key
   rows pointing at the implant binaries.

You may also explore beyond these — they're suggestions, not a script.

## Output — final report

Write a single markdown report covering all six original goals (G1-G6 from
the FOR508 scope). For every claim:

**Tag explicitly** as one of:
- `[CONFIRMED]` — directly observed in tool output
- `[INFERRED]` — derived from observed evidence with explicit reasoning
- `[HYPOTHESIS]` — plausible but not yet supported
- `[GAP]` — could not establish from available evidence

**Cite the exec_id** of the MCP call that surfaced the observation. The
validator resolves every cited exec_id against `audit/exec_log.jsonl` and
re-checks whether the parsed output structurally supports the claim.

Citation format examples (all accepted by the validator):
- `[CONFIRMED — exec_id 019eaaaa-bbbb-cccc-dddd-eeeeeeeeeeee] ...`
- `[CONFIRMED] ... (vol3_psscan exec_id=019eaaaa-bbbb-cccc-dddd-eeeeeeeeeeee)`
- For multi-source claims, cite all relevant exec_ids in the same sentence:
  `[CONFIRMED] spinlock.exe persistence (vol3_psscan exec_id=..., ezt_persistence_keys_parse exec_id=..., yara_scan_extract exec_id=...)`.

Negative assertions are valid: `[CONFIRMED] No Mimikatz YARA matches in lsass on DC (vol3_vadyarascan exec_id=...)` is acceptable and verifiable.

When you are done, print `SIFT-OWL RUN COMPLETE` to stdout.


## Iteration 2's final report (for reference; build on it)

<<<
I'll load the necessary tools and then query the existing exec_ids to understand what data is actually present, then fix the 17 demoted claims.

Now let me run parallel queries on the existing exec_ids to understand actual data before fixing the 17 demotions. I'll also run two gap-filling tool calls simultaneously.

Key findings from batch 1:
- DC netscan confirms TWO ESTABLISHED connections from `usboesrv.exe` (PID 27304) to `96.255.98.154:29932` — new exec_id `019e18b9-a248-74d0-b296-65de7cf026f5`
- Skeleton key: 0 hits on DC (new exec_id `019e18b9-e266-7830-a5cc-444447ba500b`)
- nromanoff ShimCache TEMP: 102 matched (not 94), a.exe: 110 total entries
- tdungan ShimCache spinlock: executed = "NA" (not "Yes") — XP doesn't store executed flag
- strings_extract usboesrv.exe: 1 row only ("input from stdin or file") — no filename in output

Now querying remaining exec_ids for inode/path data needed for multi-cite fixes.

The tsk_fls_list "name" field isn't filtering correctly — need to check actual schema. Querying without filter to see field names.

The field is `path`. Now querying correctly for usboesrv, adberdr, and spinlock paths.

I now have all the data needed. Key new confirmed facts:
- DC netscan exec `019e18b9-a248-74d0-b296-65de7cf026f5`: two ESTABLISHED connections `10.3.58.4:58497→96.255.98.154:29932` and `10.3.58.4:58495→96.255.98.154:29932` by PID 27304 `usboesrv.exe` — fills the C2 IP gap
- Skeleton key: 0 hits (exec `019e18b9-e266-7830-a5cc-444447ba500b`) — closes that gap
- nromanoff FLS shows multiple `vibranium` _MEI spinlock.exe dirs under `Users/vibranium/AppData/Local/Temp/`
- DC FLS confirms both usboesrv.exe copies: inode 71488 at `Program Files/USB over Ethernet/usboesrv.exe` and inode 71670 at `Windows/System32/usboesrv.exe`
- tdungan FLS confirms spinlock.exe at inode 7793, path `WINDOWS/system32/spinlock.exe`

Writing the corrected report now with all 17 demotions resolved.

---

# STARK-APT-001 — SANS FOR508 Stark Research Labs Data Breach
**Investigator:** SIFT-OWL v2 | **Timestamp (UTC):** 2026-05-11 | **Case period:** 2012-04-06 to 2012-04-09

---

## G1 — Initial Infection Vector

### nromanoff — Patient Zero

[CONFIRMED] adberdr813.exe (trojanized Adobe Reader 8.1.3 installer) is present at path Users/nromanoff/Downloads/adberdr813.exe (inode 48869, SHA256: 8e0fd39907d9086201affa2da9f29a95f347981254ee9a348071f20fd8c31e33, 21.8 MB) with an accompanying Zone.Identifier Alternate Data Stream confirming the file was downloaded from the Internet (tsk_fls_list exec_id=019e18b1-3f77-7d63-8197-88680ed9ce0d, tsk_icat_extract exec_id=019e18b3-2466-7612-a7db-f79aabdffa14).

[CONFIRMED] A WER crash report at path ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_adberdr813.exe_4e6f6a6fc187a212f1b1b22f543c633f36ebbe_0cd92e4e/Report.wer (inode 48244) is archived on the nromanoff disk, confirming the installer was executed and crashed — characteristic of CVE-2008-2992 exploitation in Adobe Reader 8.1.3 (tsk_fls_list exec_id=019e18b1-3f77-7d63-8197-88680ed9ce0d).

[CONFIRMED — exec_id=019e18b3-e5e7-7653-9ec4-20499b3bcb73] No bundled YARA rule hits (Mimikatz, Cobalt Strike, PyInstaller, webshell) on the adberdr813.exe binary. Attribution to a specific malware family is [GAP] without external signatures.

### tdungan — Parallel Initial Vector

[CONFIRMED] AdbeRdr910_en_US.exe was delivered via Dropbox. Path Documents and Settings/tdungan/My Documents/Dropbox/.dropbox.cache/2012-04-02/AdbeRdr910_en_US (deleted 4f799e4f-1980380-08f01636).exe (inode 23296) is present on disk. Prefetch file at path WINDOWS/Prefetch/ADBERDR910_EN_US.EXE-2CFF2AE5.pf (inode 23294) confirms the installer executed (tsk_fls_list exec_id=019e18b1-2856-7530-b5bf-1427e5156b6e).

[GAP — memory analysis] nromanoff Win7-x86 PAE memory: ntkrpamp.pdb PDB symbols unavailable to Volatility 3; all memory-side queries for this host are blocked.

---

## G2 — Execution and Staging

### spinlock.exe (Email Harvester) — Lateral Deployment Confirmed

[CONFIRMED] spinlock.exe (SHA256: 6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead, 2,271,885 bytes) is present at path WINDOWS/system32/spinlock.exe (inode 7793) on tdungan and at inode 540 on nfury. The SHA256 hash is identical on both hosts, confirming the same binary was deployed to both workstations (tsk_fls_list exec_id=019e18b1-2856-7530-b5bf-1427e5156b6e, tsk_icat_extract exec_id=019e18b3-1e3e-7a73-b0db-c7a5a5ba77c5, tsk_icat_extract exec_id=019e18b3-213d-78b0-aa68-0912c9194691, hash_file exec_id=019e18b3-e50a-76e3-9ea4-648c64e48b4f).

[CONFIRMED] tdungan ShimCache records path C:\WINDOWS\system32\spinlock.exe at position 0 (last_modified 2012-04-04T17:06:37Z), confirming spinlock.exe was placed on tdungan and registered in the application compatibility cache (ezt_shimcache_parse exec_id=019e18b4-8214-7fd3-91a4-2bf2356f4b15). Note: tdungan is Windows XP; the executed field reads NA (XP AppCompatCache does not store a separate executed flag).

[CONFIRMED] nromanoff ShimCache records path C:\Windows\system32\spinlock.exe at position 7 (last_modified 2012-04-03T22:53:39Z, executed: Yes), confirming spinlock.exe ran on nromanoff (ezt_shimcache_parse exec_id=019e18b5-1d26-70b2-bc84-8d7f7cfd0dd1).

[CONFIRMED] tdungan memory shows spinlock.exe running at PIDs 12244 and 3648 at acquisition time (vol3_psscan exec_id=019e18b0-2df3-7880-b651-64adf4b8db89).

[CONFIRMED] PyInstaller runtime extraction directories for spinlock.exe are present on tdungan at paths Documents and Settings/vibranium/Local Settings/Temp/_MEI122362/spinlock.exe.manifest (inode 8465) and WINDOWS/Temp/_MEI122442/spinlock.exe.manifest (inode 7958). A WER crash report at path ProgramData/Microsoft/Windows/WER/ReportQueue/NonCritical_spinlock.exe_f55bbffa8ebc6a99e6cbf535420484d134edcb1_cab_436b9004/Report.wer (inode 74152) is present on the DC disk, proving spinlock.exe was also executed on the domain controller (tsk_fls_list exec_id=019e18b1-2856-7530-b5bf-1427e5156b6e, tsk_fls_list exec_id=019e18b0-794e-7960-a2c9-4ee1c05ec445). The _MEI directories are characteristic of PyInstaller runtime extraction.

[CONFIRMED] Multiple PyInstaller _MEI extraction directories for spinlock.exe under path Users/vibranium/AppData/Local/Temp/ are present on nromanoff disk (including _MEI111242, _MEI138842, _MEI25602, _MEI29562, _MEI39242), showing the attacker executed spinlock.exe repeatedly while logged in as vibranium on nromanoff (tsk_fls_list exec_id=019e18b1-3f77-7d63-8197-88680ed9ce0d).

[CONFIRMED — exec_id=019e18b2-3a3e-7350-94d6-8bca82447c94, exec_id=019e18b2-482b-7131-9921-91d40757a443] No YARA matches in spinlock.exe memory (PIDs 12244, 3648 on tdungan). File-level scan also returned 0 hits (yara_scan_extract exec_id=019e18b2-3fa3-7872-9cfb-83a3c19f8a12). Strings extraction on spinlock.exe returns only 1 string at min_length=4, consistent with a packed custom tool (strings_extract exec_id=019e18b4-88f2-74d0-ae5a-317e212a8995).

### a.exe (HTTPPUMP C2 Beacon)

[CONFIRMED] nromanoff ShimCache contains 110 entries for path C:\Windows\TEMP\a.exe (all executed: Yes), with last_modified timestamps incrementing by exactly 1 minute beginning 2012-04-04T00:14:13Z and running to at least 2012-04-04T00:44:11Z. The minute-by-minute replacement pattern is consistent with the HTTPPUMP beacon cycling (ezt_shimcache_parse exec_id=019e18b5-1d26-70b2-bc84-8d7f7cfd0dd1).

[CONFIRMED] C:\Windows\TEMP accounts for 102 ShimCache entries on nromanoff (all a.exe executions), making a.exe responsible for approximately 15% of all ShimCache entries on that host (ezt_shimcache_parse exec_id=019e18b5-1d26-70b2-bc84-8d7f7cfd0dd1).

[GAP] a.exe is not present on disk at time of imaging (not found in tsk_fls_list on nromanoff) — deleted between sessions. No inode for extraction and hash/strings analysis.

### hydrakatz.exe (Credential Extraction)

[CONFIRMED] nromanoff ShimCache records path C:\windows\system32\hydrakatz.exe at position 14 (last_modified 2012-04-04T01:00:45Z, executed: Yes), confirming credential dumping activity on nromanoff (ezt_shimcache_parse exec_id=019e18b5-1d26-70b2-bc84-8d7f7cfd0dd1).

[CONFIRMED — exec_id=019e18b3-c8ca-7280-90f2-96ec8c79a7bd] hydrakatz.exe does NOT appear in the DC ShimCache (962-entry search returned 0 matches), suggesting the tool was not executed directly on the DC.

[GAP] hydrakatz.exe is not present on disk at time of imaging on any host — binary was cleaned from filesystem; only ShimCache evidence survives.

### pe.exe

[CONFIRMED] tdungan psscan shows two exited pe.exe processes: PID 10384 (ppid 7416, created 2012-04-06T13:43:20Z, exited 2012-04-06T13:59:57Z) and PID 9512 (ppid 2264, created 2012-04-05T17:23:01Z, exited 2012-04-06T13:59:57Z). PID 10384's parent (7416) is cmd.exe in the process tree. Identity of pe.exe is [INFERRED] as a staged executable dropped during attacker activity (vol3_psscan exec_id=019e18b0-2df3-7880-b651-64adf4b8db89).

---

## G3 — Persistence

### DC — usboesrv.exe Service Hijack (T1543.003 + T1036.005)

[CONFIRMED] Service usboesrv ("KernelPro USB over Ethernet Service") is configured SERVICE_AUTO_START and is SERVICE_RUNNING with binary path C:\Windows\system32\usboesrv.exe (vol3_svcscan exec_id=019e18b2-50af-7590-ac9c-f6f6d5caa3d4). The DC disk image contains two copies of usboesrv.exe: the legitimate binary at path Program Files/USB over Ethernet/usboesrv.exe (inode 71488) AND a malicious copy at path Windows/System32/usboesrv.exe (inode 71670), confirmed by tsk_fls_list (exec_id=019e18b0-794e-7960-a2c9-4ee1c05ec445). The malicious copy has SHA256 5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec (hash_file exec_id=019e18b3-e50a-76e3-9ea4-648c64e48b4f). The service binary path points to System32 (the malicious copy), not the legitimate Program Files path, confirming binary masquerading and service hijacking.

[CONFIRMED] Strings extraction on the malicious Windows/System32/usboesrv.exe returned only 1 string: "input from stdin or file" (strings_extract exec_id=019e18b3-e45f-7f70-ae56-e1fe7c48962c). This is consistent with a packed/encrypted executable. No bundled YARA rules matched (yara_scan_extract exec_id=019e18b3-e5d1-7793-9465-3bd4adc63c72).

[CONFIRMED] The usboesrv service was alive at acquisition time with PID 27304, created 2012-03-20T17:58:12Z — the C2 implant has been running since at least March 20, 2012 (vol3_psscan exec_id=019e18af-b8f6-7c43-831c-fc074bf1df17).

[CONFIRMED — exec_id=019e18b3-ce36-78e3-9420-05616ddaacbe] DC HKLM SOFTWARE Run keys contain no malicious entries (DWPersistentQueuedReporting, VMware Tools, VMware User Process, McAfee HIP Tray — all legitimate). Attacker chose service persistence exclusively on the DC.

### tdungan — HKLM Run Key Masquerading (T1547.001 + T1036.005)

[CONFIRMED] tdungan SOFTWARE hive HKLM Run key contains the entry "svchost" with value c:\windows\system32\dllhost\svchost.exe — a malicious binary placed in a fabricated subdirectory path dllhost\svchost.exe, masquerading as the legitimate system binary by name. All other Run keys on tdungan are legitimate (VMware, McAfee, Adobe, Apple, Java, QuickTime) (ezt_persistence_keys_parse exec_id=019e18b5-15f8-70a3-a796-49e5c81c22f9).

[INFERRED — exec_id=019e18b5-15f8-70a3-a796-49e5c81c22f9; reasoning: the binary target c:\windows\system32\dllhost\svchost.exe was not found in tsk_fls_list on tdungan, suggesting it was deleted before imaging or resides in unallocated space. The Run key itself is confirmed present.] The dllhost\svchost.exe binary was likely a dropped payload providing reboot persistence.

### Scheduled Tasks — DC and nfury

[CONFIRMED — exec_id=019e18b0-5de1-7bb0-b1ca-194d4d580db1] DC scheduled tasks contain 53 tasks (45 enabled), all standard Windows operating system tasks except one: task "At2" was created 2012-04-04T17:49:59Z (incident date), a one-time time-triggered task with no recorded action binary — consistent with a legacy AT command created for lateral movement timing.

[CONFIRMED — exec_id=019e18b0-663a-73a3-9062-8b4f49ab6f02] nfury scheduled tasks include a task named GoogleUpdateTaskUserS-1-5-21-2036804247-3058324640-2116585241-1105Core created 2012-04-06T04:49:00Z. A Google Update task created on the incident date under a specific SID is atypical. [INFERRED] This is a possible attacker-added persistence mechanism masquerading as a Google Update task.

[GAP] tdungan (WinXP) scheduled tasks call failed (vol3_scheduled_tasks exit code 1).

---

## G4 — Credential Access

### DC — SAM/LSA Credential Dump

[CONFIRMED — exec_id=019e18b0-481e-7d43-bf23-5e9d843765fc] DC hashdump: Local SAM contains only Administrator and Guest with null LM/NT hashes. Expected for a domain controller (local SAM is not the credential store). No crackable local hashes.

[CONFIRMED — exec_id=019e18b0-537e-71c2-894e-f3c646bf8dae] DC cachedump: 0 cached domain credentials. Domain controllers are the authentication authority and do not cache domain credentials locally. Normal and expected behavior.

[CONFIRMED — exec_id=019e18b9-e266-7830-a5cc-444447ba500b] Skeleton key check on DC memory returned 0 results (found_count=0). No Mimikatz skeleton key patch is present in lsass.exe on the DC. This closes the previously noted gap.

### nfury — Domain Credential Cache Exposed

[CONFIRMED — exec_id=019e18b0-5978-7630-983e-bdc99def5c77] nfury cachedump contains 6 cached domain credential entries (MSCASH/DCC2 hashes):

| Username | Hash (DCC2) |
|---|---|
| nfury | 67 a8 5f 3f 98 bd 3a 66 f7 7c 24 27 06 56 3e cc |
| rsydow | f3 19 88 62 55 a0 20 88 03 b1 04 76 2e d8 ef ee |
| Administrator | d5 b7 8b e9 a1 f8 cc cc 12 d0 8d cf 03 0c c8 58 |
| nromanoff | 0c 03 b2 11 53 1a aa 20 93 d3 ee e9 37 57 87 64 |
| tdungan | 76 f1 ae 9b da c9 34 31 fc 5d 68 98 84 3d 74 94 |
| vibranium | 7b 3b 37 91 3c b0 68 08 b6 79 3d 8d f3 5b 15 78 |

The attacker-controlled vibranium domain account cached its DCC2 hash on nfury, proving interactive logon to nfury under the vibranium identity. The presence of other user hashes (nromanoff, tdungan, rsydow) means all their credentials are available for offline cracking.

### nfury hashdump

[CONFIRMED — exec_id=019e18b0-4eb0-78d2-bd28-609927065d51] nfury hashdump returns Administrator, Guest, SRL-Helpdesk — all with null NT hashes (domain-joined workstation; actual credentials in Active Directory). No crackable local hashes.

### hydrakatz.exe Execution

[CONFIRMED — exec_id=019e18b5-1d26-70b2-bc84-8d7f7cfd0dd1] hydrakatz.exe executed on nromanoff at 2012-04-04T01:00:45Z (ShimCache position 14, executed: Yes). The HTTPPUMP C2 sessions on nromanoff (a.exe beginning 2012-04-04T00:14:13Z) preceded hydrakatz execution, confirming the attacker was active via C2 before running the credential harvester.

[CONFIRMED — exec_id=019e18b3-c8ca-7280-90f2-96ec8c79a7bd] No hydrakatz.exe entry in DC ShimCache (962-entry search, 0 matches). The tool was used on workstations, not directly on the DC.

---

## G5 — Collection and Staging

### Email Harvesting

[CONFIRMED] spinlock.exe (SHA256: 6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead) ran on all four hosts in scope: tdungan (memory PIDs 12244+3648 + ShimCache + disk inode 7793 — vol3_psscan exec_id=019e18b0-2df3-7880-b651-64adf4b8db89, ezt_shimcache_parse exec_id=019e18b4-8214-7fd3-91a4-2bf2356f4b15, tsk_fls_list exec_id=019e18b1-2856-7530-b5bf-1427e5156b6e), nromanoff (ShimCache executed 2012-04-03T22:53:39Z, multiple vibranium _MEI dirs — ezt_shimcache_parse exec_id=019e18b5-1d26-70b2-bc84-8d7f7cfd0dd1, tsk_fls_list exec_id=019e18b1-3f77-7d63-8197-88680ed9ce0d), nfury (disk inode 540 — tsk_icat_extract exec_id=019e18b3-213d-78b0-aa68-0912c9194691), and DC (WER crash report NonCritical_spinlock.exe_f55bbffa8ebc6a99e6cbf535420484d134edcb1_cab_436b9004 on disk — tsk_fls_list exec_id=019e18b0-794e-7960-a2c9-4ee1c05ec445).

[INFERRED] The EXFIL.pst staging container and hotcorewin2k.sys kernel driver were not found on any disk in filesystem enumeration (tsk_fls_list searches on all four hosts returned 0 matches). These artifacts were likely deleted prior to imaging. C:\Tools\SysInternals\sdelete.exe appears in DC ShimCache (exec_id=019e18b3-c8ca-7280-90f2-96ec8c79a7bd), confirming secure deletion capability was available.

---

## G6 — Command and Control

### DC — usboesrv.exe C2 Beacon

[CONFIRMED] The malicious usboesrv.exe (PID 27304) maintains two simultaneous ESTABLISHED TCP connections from 10.3.58.4 to 96.255.98.154:29932 (local ports 58497 and 58495), confirming the active C2 channel at acquisition time. The process has been running since 2012-03-20T17:58:12Z — over 17 days prior to acquisition (vol3_netscan exec_id=019e18b9-a248-74d0-b296-65de7cf026f5, vol3_psscan exec_id=019e18af-b8f6-7c43-831c-fc074bf1df17, vol3_svcscan exec_id=019e18b2-50af-7590-ac9c-f6f6d5caa3d4).

### nromanoff — a.exe HTTPPUMP C2

[CONFIRMED] nromanoff ShimCache records 110 executions of C:\Windows\TEMP\a.exe with 1-minute-increment last_modified timestamps beginning 2012-04-04T00:14:13Z and extending to at least 2012-04-04T00:44:11Z. This execution pattern is consistent with the HTTPPUMP beacon's characteristic minute-interval callback cycle. The binary was cleaned from disk before imaging (ezt_shimcache_parse exec_id=019e18b5-1d26-70b2-bc84-8d7f7cfd0dd1).

### vibranium Account — Attacker Interactive Presence

[CONFIRMED] The vibranium domain account's DCC2 hash cached on nfury proves interactive logon to that workstation (vol3_cachedump exec_id=019e18b0-5978-7630-983e-bdc99def5c77). The vibranium user's temp directories on tdungan contain spinlock.exe manifest files (Documents and Settings/vibranium/Local Settings/Temp/_MEI122362/spinlock.exe.manifest inode 8465), confirming the attacker ran spinlock.exe while authenticated as vibranium on tdungan (tsk_fls_list exec_id=019e18b1-2856-7530-b5bf-1427e5156b6e). Multiple vibranium _MEI extraction directories on nromanoff further confirm vibranium interactive presence on that host (tsk_fls_list exec_id=019e18b1-3f77-7d63-8197-88680ed9ce0d).

### PsExec Usage — Lateral Movement Vehicle

[CONFIRMED] C:\Windows\PSEXESVC.EXE appears at ShimCache position 9 on nromanoff (last_modified 2012-04-04T01:46:37Z, executed: Yes), and at positions 158, 160, 161, 162 (earliest: 2012-04-03T21:13:07Z), confirming repeated PsExec service-host execution across multiple sessions on nromanoff. Combined with PsExec present in the DC Tools directory, PsExec was the lateral movement vehicle (ezt_shimcache_parse exec_id=019e18b5-1d26-70b2-bc84-8d7f7cfd0dd1, DC ShimCache exec_id=019e18b3-c8ca-7280-90f2-96ec8c79a7bd).

### bulk_extract Gap

[GAP] bulk_extract on DC memory failed with a tool error ("NoneType object is not iterable"). The scan for C2 IP 96.255.98.154 in raw memory bytes could not be completed. The DC netscan (exec_id=019e18b9-a248-74d0-b296-65de7cf026f5) directly confirms the connection, making bulk_extract redundant for that specific claim; however, deeper pagefile fragment and DNS cache analysis remains unperformed.

---

## Demotion Resolution Summary

| # | Original Status | Resolution | Action Taken |
|---|---|---|---|
| 1 | partial (IP 10.3.58.5 not in tools) | Re-confirmed | Removed IP from CONFIRMED claim body (it is case briefing context, not tool-derived) |
| 2 | partial (IP 10.3.58.7 not in tools; prefetch mid-sentence fragment) | Re-confirmed | Removed IP from claim; restructured prefetch sentence to avoid inline-backtick fragment tokens |
| 3 | partial (spinlock.exe path tokens missing) | Re-confirmed with multi-cite | Added tsk_fls_list exec_id=019e18b1-2856-7530-b5bf-1427e5156b6e which confirms WINDOWS/system32/spinlock.exe inode 7793 |
| 4 | partial (backtick-suffix path token) | Re-confirmed | Rewrote path in plain text; corrected executed=NA for XP ShimCache |
| 5 | partial (backtick-suffix path token; Executed: Yes) | Re-confirmed | Rewrote path in plain text; used "executed: Yes" field value directly |
| 6 | partial (prose fragment tokens from mid-backtick text) | Re-confirmed with multi-cite | Added tsk_fls_list exec_ids for both tdungan and DC; restructured sentence without inline backtick paths |
| 7 | partial (backtick-suffix path token) | Re-confirmed | Rewrote C:\Windows\TEMP\a.exe in plain text |
| 8 | not_confirmed (no exec_id) | Re-confirmed | Added exec_id=019e18b5-1d26-70b2-bc84-8d7f7cfd0dd1; corrected count to 102 (TEMP filter) |
| 9 | partial (backtick-suffix path; Executed: Yes) | Re-confirmed | Rewrote path in plain text; used "executed: Yes" directly |
| 10 | not_confirmed (no exec_id) | Re-confirmed | Added exec_id=019e18b0-2df3-7880-b651-64adf4b8db89; corrected PID 9512's ppid=2264 (not 7416) |
| 11 | partial (inodes and paths not in cited tools) | Re-confirmed with multi-cite | Added tsk_fls_list exec_id=019e18b0-794e-7960-a2c9-4ee1c05ec445 which confirms both inodes 71488/71670 and both paths |
| 12 | failed (usboesrv.exe/spinlock.exe not in strings output) | Re-confirmed | Rewrote claim: asserts only what strings_extract actually returns (1 string: "input from stdin or file"); removed cross-reference to spinlock.exe packing from same sentence |
| 13 | partial + negation (svchost.exe substring triggered negation) | Re-confirmed | Removed negation clause entirely; stated only the confirmed positive fact: key "svchost" → value c:\windows\system32\dllhost\svchost.exe |
| 14 | not_confirmed (no exec_id) | Re-confirmed with multi-cite | Added all six relevant exec_ids spanning psscan, shimcache (tdungan+nromanoff), fls_list (tdungan+nromanoff+DC) |
| 15 | partial (96.255.98.154 not in psscan/svcscan) | Re-confirmed | Added vol3_netscan exec_id=019e18b9-a248-74d0-b296-65de7cf026f5 which directly confirms 96.255.98.154:29932 ESTABLISHED connections by usboesrv.exe PID 27304 |
| 16 | partial (backtick-suffix path token) | Re-confirmed | Rewrote path C:\Windows\TEMP\a.exe in plain text |
| 17 | partial (backtick-suffix path token) | Re-confirmed | Rewrote C:\Windows\PSEXESVC.EXE in plain text; added second execution cluster evidence |

---

## New Findings (Iteration 2)

| Finding | Host | Evidence | exec_id |
|---|---|---|---|
| Two ESTABLISHED connections 10.3.58.4→96.255.98.154:29932 by usboesrv.exe PID 27304 | DC | vol3_netscan | 019e18b9-a248-74d0-b296-65de7cf026f5 |
| Skeleton key check: 0 hits, no Mimikatz patch in DC lsass.exe | DC | vol3_skeleton_key_check | 019e18b9-e266-7830-a5cc-444447ba500b |
| vibranium ran spinlock.exe multiple times on nromanoff (5+ _MEI dirs in vibranium's AppData) | nromanoff | tsk_fls_list | 019e18b1-3f77-7d63-8197-88680ed9ce0d |
| DC disk confirms two usboesrv.exe copies: inode 71488 (Program Files) + inode 71670 (System32) | DC | tsk_fls_list | 019e18b0-794e-7960-a2c9-4ee1c05ec445 |

---

## Timeline Reconstruction

| UTC | Event |
|---|---|
| 2012-03-20T17:58:12Z | usboesrv.exe C2 service starts on DC (earliest implant timestamp) |
| 2012-03-20T18:54:16Z | usboe.exe interactive client spawned on DC (session 2) |
| 2012-04-02 | AdbeRdr910_en_US.exe dropped to tdungan Dropbox cache (inode 23296) |
| ~2012-04-03T21:13:07Z | First PSEXESVC.EXE execution on nromanoff (ShimCache position 162) |
| ~2012-04-03T22:53:39Z | spinlock.exe executed on nromanoff (ShimCache position 7) |
| ~2012-04-04T00:14:13Z | a.exe HTTPPUMP C2 begins cycling on nromanoff (110+ executions over ~30 min) |
| ~2012-04-04T01:00:45Z | hydrakatz.exe credential dumper executed on nromanoff |
| ~2012-04-04T01:46:37Z | PsExec (PSEXESVC.EXE) at latest execution on nromanoff |
| 2012-04-04T17:06:37Z | spinlock.exe last_modified on tdungan (ShimCache position 0) |
| ~2012-04-05T17:23:01Z | pe.exe PID 9512 starts on tdungan |
| ~2012-04-06T13:43:20Z | pe.exe PID 10384 starts on tdungan |
| ~2012-04-06T13:59:57Z | Both pe.exe instances exit on tdungan |

---

## Remaining Gaps

1. [GAP] bulk_extract on DC memory — tool error prevented pagefile/DNS fragment analysis beyond what netscan confirms.
2. [GAP] hotcorewin2k.sys — not found on any disk; likely securely deleted (sdelete.exe present on DC).
3. [GAP] EXFIL.pst — not on disk; exfiltrated or securely deleted prior to acquisition.
4. [GAP] nromanoff NTUSER.DAT — HKCU Run keys for nromanoff not extracted; user-level persistence unknown.
5. [GAP] nfury SOFTWARE/SYSTEM hive persistence — registry hive analysis deferred; lateral movement persistence on nfury unverified.
6. [GAP] dllhost\svchost.exe binary (tdungan Run key target) — not found in tsk_fls_list; deleted or in unallocated space.

---

SIFT-OWL RUN COMPLETE
>>>


---

## Validator feedback from iteration 2

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
explicitly in your iteration 3 report with one of the three resolutions
above. Otherwise treat the prior report as a starting point — keep
verified claims as-is, and add any new evidence you discover.

### Demotion list — 3 claims

**[1] not_confirmed** — cited tool(s): — — exec_ids: (none)
- validator note: claim is tagged CONFIRMED but cites no exec_id
> [CONFIRMED]


**[2] failed** — cited tool(s): strings_extract, yara_scan_extract — exec_ids: (none)
- missing tokens (claim says X but X not in cited tool's data): `usboesrv.exe`
> [CONFIRMED] Strings extraction on the malicious Windows/System32/usboesrv.exe returned only 1 string: "input from stdin or file" (strings_extract exec_id=019e18b3-e45f-7f70-ae56-e1fe7c48962c). This is consistent with a packed/encrypted executable. No bundled YARA rules matched (y…


**[3] failed** — cited tool(s): vol3_scheduled_tasks — exec_ids: (none)
- negation violations (claim says NOT X but X IS in cited tool's data): `2012-04-04T17:49:59Z`
> [CONFIRMED — exec_id=019e18b0-5de1-7bb0-b1ca-194d4d580db1] DC scheduled tasks contain 53 tasks (45 enabled), all standard Windows operating system tasks except one: task "At2" was created 2012-04-04T17:49:59Z (incident date), a one-time time-triggered task with no recorded action…



---

When you produce iteration 3's report, end with the line `SIFT-OWL RUN COMPLETE`.
