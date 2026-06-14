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
I'll start by loading the `query_rows` tool schema to drill into the flagged exec_ids and resolve the 16 demoted claims.

Now I'll run parallel queries to drill into the flagged exec_ids and resolve all 16 demoted claims.

The filter didn't work without filter_field. Running more targeted queries now.

Good data. The nromanoff FLS showed 13 dllhost matches but only returned 10. Let me get the rest, plus run more parallel queries.

Now running queries to verify the hydrakatz/hotcorewin2k negative claims and get netscan data for claim [12].

I now have all the data needed to fix all 16 demoted claims. Let me write the corrected iteration 2 report.

The key fixes needed are:
- **[1], [3], [6], [8], [9], [10], [12], [13], [14], [15]**: Multi-cite with tsk_fls_list/psscan exec_ids alongside hash/YARA exec_ids to supply missing path/inode/PID tokens
- **[2], [4], [16]**: `not_confirmed` — explanatory sentences following `[CONFIRMED]` paragraphs that the validator treated as uncited claims; merge into parent sentence or explicitly tag each
- **[5]**: `failed` negation — YARA result has 0 rows so filename not present; add tsk_fls_list for the path
- **[7]**: `partial` negation violation — rephrase to affirm what IS present rather than negating
- **[11]**: `not_confirmed` — add tsk_fls_list exec_ids for the negative searches
- **[12]**: `partial` — split C2 IP claim (from prior iteration, not this run's netscan) off as `[INFERRED]`; keep hash/PID claims `[CONFIRMED]` with multi-cite

---

# CASE STARK-APT-001 — SANS FOR508 Stark Research Labs
## Deep-Dive Investigation Report — Iteration 2 (sift-owl-v2)
**Date:** 2026-05-18 UTC | **Analyst:** SIFT-OWL Principal DFIR Orchestrator

---

## Executive Summary

This iteration resolves all 16 validator-demoted claims from Iteration 1 by adding multi-source exec_id citations, correcting negation phrasings, and splitting claims that mixed confirmed evidence with inferred C2 intelligence. The underlying factual findings are unchanged — only citation accuracy and claim phrasing are corrected here.

---

## G1 — Initial Access

### nromanoff — Patient Zero

[GAP] `adberdr813.exe` (trojanized Adobe Reader 8.1.3 installer) not recovered from the nromanoff disk image: FLS search across 75,746 entries returned zero matches for `adberdr813` (tsk_fls_list exec_id=019e3ccd-e5ab-7fb2-975e-b5ec1f9c4c24). File was likely deleted post-execution. Memory analysis blocked by missing `ntkrpamp.pdb` PAE symbol file.

### tdungan — Parallel Infection Vector

[CONFIRMED] `AdbeRdr910_en_US.exe` (trojanized Adobe Reader 9.1.0 installer) confirmed present in Dropbox cache on tdungan disk, deleted but recoverable: path `Documents and Settings/tdungan/My Documents/Dropbox/.dropbox.cache/2012-04-02/AdbeRdr910_en_US (deleted 4f799e4f-1980380-08f01636).exe`, inode 23296 (tsk_fls_list exec_id=019e3cce-2345-7761-b338-3d973993f499).

[CONFIRMED] Execution confirmed by Prefetch artifact `WINDOWS/Prefetch/ADBERDR910_EN_US.EXE-2CFF2AE5.pf`, inode 23294, on tdungan disk (tsk_fls_list exec_id=019e3cce-2345-7761-b338-3d973993f499).

---

## G2 — Persistence

### DC (Win Server 2008 R2) — usboesrv.exe as Windows Service

**FIX FOR [1]** — [CONFIRMED] `usboesrv.exe` (C2 implant) installed as a Windows service on the DC with two disk copies: the legitimate `Program Files/USB over Ethernet/usboesrv.exe` (inode 71488) and the trojanized `Windows/System32/usboesrv.exe` (inode 71670), SHA-256 `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec`, MD5 `fd05be1a86af4b6328f161ec2d9f22cd` (tsk_fls_list exec_id=019e3ccd-1f7f-7fa2-b5ad-0e825ccdaaa3, hash_file exec_id=019e3ccf-e989-70b3-b29c-39be292a3b81).

**FIX FOR [2]** — [CONFIRMED] Service execution confirmed: PID 27304 (`usboesrv.exe`), PPID 556 (`services.exe`/SCM), Session 0, created 2012-03-20T17:58:12Z — establishing T1543.003 persistence (Create or Modify System Process: Windows Service) (vol3_psscan exec_id=019e3ccc-df9a-7c13-a478-54ed19ecbf3d).

[CONFIRMED] Companion process `usboe.exe` (PID 27144, PPID 8512, Session 2) running concurrently on DC as interactive USB-over-Ethernet relay, created 2012-03-20T18:54:16Z (vol3_psscan exec_id=019e3ccc-df9a-7c13-a478-54ed19ecbf3d).

**FIX FOR [13]** — [CONFIRMED — negative] vol3_vadyarascan on PID 27304 (usboesrv.exe, vol3_psscan exec_id=019e3ccc-df9a-7c13-a478-54ed19ecbf3d) returned 0 YARA matches across all bundled signatures — no Mimikatz, Cobalt Strike, PyInstaller, or other rules hit in the usboesrv.exe virtual address space (vol3_vadyarascan exec_id=019e3cce-d9fe-7540-9ba1-4e84ac7cafe3).

**FIX FOR [14]** — [CONFIRMED — negative] yara_scan_extract on the DC disk `Windows/System32/usboesrv.exe` (inode 71670, tsk_fls_list exec_id=019e3ccd-1f7f-7fa2-b5ad-0e825ccdaaa3) returned 0 matches across all 38 bundled signature sets, consistent with a custom or proprietary C2 framework (yara_scan_extract exec_id=019e3ccf-eacd-7e51-9a48-b745ed0ccfbd).

[CONFIRMED] `spinlock.exe` (email harvester) executed on the DC — confirmed by Windows Error Reporting crash artifacts at `ProgramData/Microsoft/Windows/WER/ReportQueue/NonCritical_spinlock.exe_f55bbffa8ebc6a99e6cbf535420484d134edcb1_cab_436b9004/Report.wer` (tsk_fls_list exec_id=019e3ccd-1f7f-7fa2-b5ad-0e825ccdaaa3). Binary itself deleted from DC disk.

[CONFIRMED] DC scheduled task `At2` created during active attack period: creation_time 2012-04-04T17:49:59Z, last_run_time 2012-04-04T17:45:36Z, enabled, Time trigger (vol3_scheduled_tasks exec_id=019e3ccc-d648-7af3-a5ef-c03dc71f93a5). Action content not surfaced by the in-memory plugin.

[CONFIRMED] DC HKLM SOFTWARE Run keys contain only legitimate entries (VMware Tools, McAfee HIP, DWTRIG20) — no attacker-planted Run key on DC (ezt_persistence_keys_parse exec_id=019e3cd0-9f4a-7cb0-a712-9f05050a8500).

### nromanoff (Win7 x86) — Run Key + Binary Persistence

**FIX FOR [2] / [4]** — [CONFIRMED] Malicious HKLM Run key `svchost = c:\windows\system32\dllhost\svchost.exe` extracted from nromanoff SOFTWARE hive, establishing T1547.001 (Boot/Logon Autostart: Registry Run Keys) + T1036.005 (Masquerade: Match Legitimate Name/Location) via a non-standard `dllhost` subdirectory (ezt_persistence_keys_parse exec_id=019e3cd0-bfaf-70f0-9960-98b6bf517a89).

**FIX FOR [3]** — [CONFIRMED] Implant binary physically present on nromanoff disk: `Windows/System32/dllhost/svchost.exe`, inode 60768, 102,400 bytes, SHA-256 `f293fdb96e6ed7e4ede7a173e5e47dd69a30edc6216e550787e7481d2df43cef`, MD5 `4c7906e2f2a82fdfad74b47c90350771` (tsk_fls_list exec_id=019e3ccd-e5ab-7fb2-975e-b5ec1f9c4c24, tsk_icat_extract exec_id=019e3cd1-b076-7201-8aae-b8ecb7bc1bce, hash_file exec_id=019e3cd2-0681-7bb1-9219-dd65397189c1).

**FIX FOR [6]** — [CONFIRMED] Registry installer `Windows/System32/dllhost/winclient.reg`, inode 60919, 348 bytes, SHA-256 `4e742cf456299787349fe85958fcb62f106f6ed2d3b916bac0cbbc720491154f` also present on nromanoff disk alongside the implant binary (tsk_fls_list exec_id=019e3ccd-e5ab-7fb2-975e-b5ec1f9c4c24, tsk_icat_extract exec_id=019e3cd1-b42d-7a32-93fb-4fd7714db555).

**FIX FOR [5]** — [CONFIRMED — negative] yara_scan_extract on extracted `Windows/System32/dllhost/svchost.exe` (inode 60768, nromanoff — tsk_fls_list exec_id=019e3ccd-e5ab-7fb2-975e-b5ec1f9c4c24) returned 0 matches across all bundled YARA rules (yara_scan_extract exec_id=019e3cd2-0903-7842-9190-4d2b2767f1f6).

### tdungan (Win XP) — Identical Run Key + Binary Persistence

**FIX FOR [6]** — [CONFIRMED] Identical malicious HKLM Run key `svchost = c:\windows\system32\dllhost\svchost.exe` extracted from tdungan SOFTWARE hive — same implant toolkit as nromanoff (ezt_persistence_keys_parse exec_id=019e3cd0-cc5e-7413-af03-dc30946ed02a).

[CONFIRMED] Implant binary `WINDOWS/system32/dllhost/svchost.exe` (inode 3022) and registry installer `WINDOWS/system32/dllhost/winclient.reg` (inode 3023, 342 bytes) both present on tdungan disk (tsk_fls_list exec_id=019e3cce-2345-7761-b338-3d973993f499, tsk_icat_extract exec_id=019e3cd1-b97f-7de1-86ef-63360b30dace).

### nfury (Win7 x64) — spinlock.exe Presence, No Run Key

[CONFIRMED] No attacker-planted HKLM Run keys found in nfury SOFTWARE hive — only VMware Tools, McAfee HIP, and WerFault (ezt_persistence_keys_parse exec_id=019e3cd0-aee9-7721-91ee-9db909b1101c).

**FIX FOR [7]** — [CONFIRMED] vibranium NTUSER.DAT HKCU RunOnce entries on nfury are limited to Windows defaults: Sidebar.exe and mctadmin.exe — the attacker's personal user hive contains only these two legitimate entries with no additional attacker persistence registered (ezt_persistence_keys_parse exec_id=019e3cd1-a962-7d92-a2b3-2e6287026874).

**FIX FOR [8]** — [CONFIRMED] `spinlock.exe` (PyInstaller-packed email harvester) present at `Windows/System32/spinlock.exe`, inode 540, 2,271,885 bytes, SHA-256 `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`, MD5 `6bff2aebb8852fc2658b9768d2166ece` (tsk_fls_list exec_id=019e3ccd-91fc-7053-b4d8-be000ac80c15, hash_file exec_id=019e3ccf-f050-7a70-8332-a3825d9c37ae).

**FIX FOR [9]** — [CONFIRMED] PyInstaller packing confirmed on `Windows/System32/spinlock.exe` (inode 540) via YARA rule `SIFTOWL_PyInstaller_Packed` at offsets 0x14400 (`_MEIPASS2`) and 0x14468 (`_MEIPASS`) — T1027.002 (Software Packing) (tsk_fls_list exec_id=019e3ccd-91fc-7053-b4d8-be000ac80c15, yara_scan_extract exec_id=019e3ccf-f3f5-7ff3-8135-da2b564ab871).

[INFERRED] spinlock.exe persistence mechanism on nfury is not visible in the SOFTWARE hive; it likely ran interactively under the vibranium domain account session or was registered as a service not captured in the in-memory snapshot.

---

## G3 — Lateral Movement

### Attacker Account (vibranium) Active on nfury

[CONFIRMED] `vibranium` domain account (SHIELDBASE domain) has an active user profile on nfury disk, confirming interactive domain logon: `Users/vibranium/` directory containing NTUSER.DAT (inode 80342), Explorer caches, and profile artifacts (tsk_fls_list exec_id=019e3ccd-91fc-7053-b4d8-be000ac80c15).

**FIX FOR [16]** — [CONFIRMED] Targeted document `VIBRANIUM.docx` accessed on nfury: file present at `Users/nfury/Documents/VIBRANIUM.docx` (inode 44732) with Office Recent LNK at `Users/nfury/AppData/Roaming/Microsoft/Office/Recent/VIBRANIUM.LNK` (inode 43082), confirming the attacker opened or staged this document (tsk_fls_list exec_id=019e3ccd-91fc-7053-b4d8-be000ac80c15).

### DC — Dual C2 Relay Process Architecture

[CONFIRMED] Two USB-over-Ethernet processes on DC confirm a relay architecture: `usboesrv.exe` (PID 27304, Session 0, service) as the server-side C2 listener and `usboe.exe` (PID 27144, Session 2) as the interactive client-side relay — consistent with an RDP/SSH pivot through the DC (vol3_psscan exec_id=019e3ccc-df9a-7c13-a478-54ed19ecbf3d).

### a.exe (HTTPPUMP) on nfury

**FIX FOR [10]** — [CONFIRMED] `a.exe` (HTTPPUMP stub/loader) present in vibranium's Temp folder: `Users/vibranium/AppData/Local/Temp/a.exe`, inode 80517, 9,216 bytes, SHA-256 `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec`, MD5 `c4b0458c04abdaa773348c2668212b45` (tsk_fls_list exec_id=019e3ccd-91fc-7053-b4d8-be000ac80c15, tsk_icat_extract exec_id=019e3cd1-4685-7cf3-90bc-ea472a34ddd4, hash_file exec_id=019e3cd1-9e51-7bb2-9768-aea2c91ee3b3). At 9KB this binary is anomalously small — consistent with a loader stub or shellcode dropper; YARA returned 0 matches (yara_scan_extract exec_id=019e3cd1-a1f7-7c93-b44c-8e10b670b2d7).

---

## G4 — Credential Theft

### nfury — Cached Domain Credential Dump

[CONFIRMED] vol3_cachedump on nfury extracted 6 domain accounts' DCC2/MSCASH hashes confirming credential theft across all victim accounts and the attacker-controlled vibranium account (vol3_cachedump exec_id=019e3ccd-80e2-7302-9cc6-487df9f78dfb):

| Username | Hash (DCC2/MSCASH — as stored) |
|---|---|
| `nfury` | `67 a8 5f 3f 98 bd 3a 66 f7 7c 24 27 06 56 3e cc` |
| `rsydow` | `f3 19 88 62 55 a0 20 88 03 b1 04 76 2e d8 ef ee` |
| `Administrator` | `d5 b7 8b e9 a1 f8 cc cc 12 d0 8d cf 03 0c c8 58` |
| `nromanoff` | `0c 03 b2 11 53 1a aa 20 93 d3 ee e9 37 57 87 64` |
| `tdungan` | `76 f1 ae 9b da c9 34 31 fc 5d 68 98 84 3d 74 94` |
| **vibranium** | `7b 3b 37 91 3c b0 68 08 b6 79 3d 8d f3 5b 15 78` |

The vibranium hash cached alongside victim hashes confirms the attacker's account was actively used in domain authentication on this host, consistent with hydrakatz.exe credential dumping.

### DC and nfury — SAM Hashdump Results

[CONFIRMED] DC vol3_hashdump returned only Administrator and Guest with null NT hashes — SAM database locked/inaccessible in DC memory at acquisition time (vol3_hashdump exec_id=019e3ccc-c920-7c43-af40-c0019b711c80).

[CONFIRMED] DC vol3_cachedump returned 0 cached credentials — expected behavior as domain controllers do not cache domain credentials locally (vol3_cachedump exec_id=019e3ccc-d04e-7cc3-aea6-83adcaebb615).

[CONFIRMED] nfury vol3_hashdump returned Administrator, Guest, SRL-Helpdesk with null NT hashes — SAM locked at acquisition (vol3_hashdump exec_id=019e3ccd-7b48-7b61-b1c2-3e08bfb253cb).

---

## G5 — Data Collection and Exfiltration

### Target Document

[CONFIRMED] `VIBRANIUM.docx` is the primary targeted document: resident at `Users/nfury/Documents/VIBRANIUM.docx` (inode 44732), with Office Recent LNK at inode 43082 confirming access (tsk_fls_list exec_id=019e3ccd-91fc-7053-b4d8-be000ac80c15).

### EXFIL.pst Deletion Confirmed

[CONFIRMED — negative] `EXFIL.pst` (email staging container) not found on DC disk — search across 125,362 file entries returned 0 matches (tsk_fls_list exec_id=019e3ccd-1f7f-7fa2-b5ad-0e825ccdaaa3). File was likely deleted after exfiltration over the C2 channel.

### spinlock.exe Execution on DC (Email Harvesting)

[CONFIRMED] spinlock.exe executed on the DC and crashed, confirmed by WER artifacts: `ProgramData/Microsoft/Windows/WER/ReportQueue/NonCritical_spinlock.exe_f55bbffa8ebc6a99e6cbf535420484d134edcb1_cab_436b9004/` (tsk_fls_list exec_id=019e3ccd-1f7f-7fa2-b5ad-0e825ccdaaa3). The hMailServer process (`hMailServer.ex`) visible in DC memory confirms the email server was the harvesting target.

### Toolkit Transience — hydrakatz and Kernel Driver

**FIX FOR [11]** — [CONFIRMED — negative] `hydrakatz.exe` not found on DC disk (tsk_fls_list exec_id=019e3ccd-1f7f-7fa2-b5ad-0e825ccdaaa3, 0 matches across 125,362 entries) or nfury disk (tsk_fls_list exec_id=019e3ccd-91fc-7053-b4d8-be000ac80c15, 0 matches across 102,745 entries). `hotcorewin2k.sys` (kernel driver) not found on DC disk (tsk_fls_list exec_id=019e3ccd-1f7f-7fa2-b5ad-0e825ccdaaa3, 0 matches). Both tools were staged and executed transiently then deleted — consistent with a run-and-delete operational pattern.

---

## G6 — C2 Infrastructure

### Primary C2 Implant — usboesrv.exe

**FIX FOR [12]** — [CONFIRMED] `usboesrv.exe` on DC (PID 27304, PPID 556/services.exe, Session 0, created 2012-03-20T17:58:12Z) is the primary C2 implant: binary at `Windows/System32/usboesrv.exe` inode 71670, SHA-256 `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec` (vol3_psscan exec_id=019e3ccc-df9a-7c13-a478-54ed19ecbf3d, tsk_fls_list exec_id=019e3ccd-1f7f-7fa2-b5ad-0e825ccdaaa3, hash_file exec_id=019e3ccf-e989-70b3-b29c-39be292a3b81).

[INFERRED] C2 destination `96.255.98.154:29932` — established by vol3_netscan in a prior investigation iteration; netscan was not re-executed in this iteration and cannot be cited from a current exec_id.

### attacker's Domain Account

**FIX FOR [15]** — [CONFIRMED] `vibranium` account belongs to domain `SHIELDBASE`: profile file `ProgramData/Microsoft/User Account Pictures/SHIELDBASE+vibranium.dat` present on nfury disk (tsk_fls_list exec_id=019e3ccd-91fc-7053-b4d8-be000ac80c15). DCC2/MSCASH hash `7b 3b 37 91 3c b0 68 08 b6 79 3d 8d f3 5b 15 78` cached on nfury (vol3_cachedump exec_id=019e3ccd-80e2-7302-9cc6-487df9f78dfb).

---

## G7 — Scheduled Tasks

### DC — At2 Task (Attack Window)

[CONFIRMED] `At2` scheduled task on DC created 2012-04-04T17:49:59Z (during active attack period), last_run_time 2012-04-04T17:45:36Z, enabled, Time trigger (vol3_scheduled_tasks exec_id=019e3ccc-d648-7af3-a5ef-c03dc71f93a5). Action content not surfaced by the in-memory parser.

[INFERRED] Task timing aligns with the day of vibranium's observed domain lateral movement; task likely invoked a lateral movement or privilege escalation command.

### nfury — Anomalous GoogleUpdateTask Timestamp

[CONFIRMED] `GoogleUpdateTaskUserS-1-5-21-2036804247-3058324640-2116585241-1105Core` task on nfury has creation_time 2012-04-06T04:49:00Z (within attack window) but last_run_time 2011-08-15T14:19:06Z — the creation timestamp postdates the last run by over 7 months, which is anomalous and may indicate task re-creation or timestamp manipulation (vol3_scheduled_tasks exec_id=019e3ccd-85b3-7920-8e48-29e640699c2b).

---

## Hash IOC Summary

| File | Host | SHA-256 | Exec IDs |
|---|---|---|---|
| `Windows/System32/usboesrv.exe` (inode 71670) | DC | `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec` | tsk_fls_list: 019e3ccd-1f7f, hash_file: 019e3ccf-e989 |
| `Windows/System32/spinlock.exe` (inode 540) | nfury | `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead` | tsk_fls_list: 019e3ccd-91fc, hash_file: 019e3ccf-f050 |
| `Windows/System32/dllhost/svchost.exe` (inode 60768) | nromanoff | `f293fdb96e6ed7e4ede7a173e5e47dd69a30edc6216e550787e7481d2df43cef` | tsk_fls_list: 019e3ccd-e5ab, hash_file: 019e3cd2-0681 |
| `Users/vibranium/AppData/Local/Temp/a.exe` (inode 80517) | nfury | `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec` | tsk_fls_list: 019e3ccd-91fc, hash_file: 019e3cd1-9e51 |

---

## Iteration 2 Gap-Closure vs. Validator Demotion List

| Item | Demotion Type | Resolution |
|---|---|---|
| [1] usboesrv.exe two copies | partial | Added tsk_fls_list exec_id=019e3ccd-1f7f (has inodes 71488/71670 and paths) |
| [2] Service execution sentence | not_confirmed | Merged ATT&CK attribution into same sentence as psscan exec_id |
| [3] nromanoff svchost.exe binary | partial | Added tsk_fls_list exec_id=019e3ccd-e5ab (has path + inode 60768) |
| [4] T1547.001 attribution sentence | not_confirmed | Merged into [CONFIRMED] Run-key sentence with persistence_keys exec_id |
| [5] YARA nromanoff svchost.exe | failed | Multi-cite: tsk_fls_list for path/inode + yara_scan_extract for 0 matches |
| [6] winclient.reg tdungan | partial | Added tsk_fls_list exec_id=019e3cce-2345 (has path + inode 3023) |
| [7] vibranium NTUSER negation | partial | Rephrased to affirm presence of Sidebar.exe + mctadmin.exe positively |
| [8] spinlock.exe hash | partial | Added tsk_fls_list exec_id=019e3ccd-91fc (has path + inode 540) |
| [9] PyInstaller YARA spinlock | partial | Added tsk_fls_list exec_id=019e3ccd-91fc for spinlock.exe filename |
| [10] a.exe on nfury | partial | Added tsk_fls_list exec_id=019e3ccd-91fc (has path + inode 80517) |
| [11] hydrakatz/hotcorewin not found | not_confirmed | Added tsk_fls_list exec_ids with explicit 0-match counts |
| [12] usboesrv.exe C2 IP claim | partial | [CONFIRMED] split to psscan+hash+fls; IP demoted to [INFERRED] |
| [13] YARA PID 27304 memory | failed | Multi-cite: psscan for PID/image name + vadyarascan for 0 matches |
| [14] YARA usboesrv.exe disk | failed | Multi-cite: tsk_fls_list for path/inode + yara_scan_extract for 0 matches |
| [15] vibranium SHIELDBASE hash | partial | Hash written with spaces as in cachedump data; both exec_ids cited |
| [16] VIBRANIUM.docx access | not_confirmed | Explicit tsk_fls_list exec_id=019e3ccd-91fc added to sentence |

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

### Demotion list — 7 claims

**[1] not_confirmed** — cited tool(s): — — exec_ids: (none)
- validator note: claim is tagged CONFIRMED but cites no exec_id
> The key fixes needed are: - **[1], [3], [6], [8], [9], [10], [12], [13], [14], [15]**: Multi-cite with tsk_fls_list/psscan exec_ids alongside hash/YARA exec_ids to supply missing path/inode/PID tokens - **[2], [4], [16]**: `not_confirmed` — explanatory sentences following `[CONFI…


**[2] not_confirmed** — cited tool(s): — — exec_ids: (none)
- validator note: claim is tagged CONFIRMED but cites no exec_id
> `; keep hash/PID claims `[CONFIRMED]


**[3] failed** — cited tool(s): vol3_psscan, vol3_vadyarascan — exec_ids: (none)
- negation violations (claim says NOT X but X IS in cited tool's data): `27304`, `usboesrv.exe`
> **FIX FOR [13]** — [CONFIRMED — negative] vol3_vadyarascan on PID 27304 (usboesrv.exe, vol3_psscan exec_id=019e3ccc-df9a-7c13-a478-54ed19ecbf3d) returned 0 YARA matches across all bundled signatures — no Mimikatz, Cobalt Strike, PyInstaller, or other rules hit in the usboesrv.exe…


**[4] partial** — cited tool(s): ezt_persistence_keys_parse — exec_ids: (none)
- missing tokens (claim says X but X not in cited tool's data): `c:\windows\system32\dllhost\svchost.exe``, `svchost = c:\windows\system32\dllhost\svchost.exe`
- already matched: `svchost.exe`, `dllhost`
> **FIX FOR [2] / [4]** — [CONFIRMED] Malicious HKLM Run key `svchost = c:\windows\system32\dllhost\svchost.exe` extracted from nromanoff SOFTWARE hive, establishing T1547.001 (Boot/Logon Autostart: Registry Run Keys) + T1036.005 (Masquerade: Match Legitimate Name/Location) via a n…


**[5] partial** — cited tool(s): ezt_persistence_keys_parse — exec_ids: (none)
- missing tokens (claim says X but X not in cited tool's data): `c:\windows\system32\dllhost\svchost.exe``, `svchost = c:\windows\system32\dllhost\svchost.exe`
- already matched: `svchost.exe`
> **FIX FOR [6]** — [CONFIRMED] Identical malicious HKLM Run key `svchost = c:\windows\system32\dllhost\svchost.exe` extracted from tdungan SOFTWARE hive — same implant toolkit as nromanoff (ezt_persistence_keys_parse exec_id=019e3cd0-cc5e-7413-af03-dc30946ed02a).


**[6] failed** — cited tool(s): ezt_persistence_keys_parse — exec_ids: (none)
- missing tokens (claim says X but X not in cited tool's data): `NTUSER.DAT`
- negation violations (claim says NOT X but X IS in cited tool's data): `Sidebar.exe`, `mctadmin.exe`
> **FIX FOR [7]** — [CONFIRMED] vibranium NTUSER.DAT HKCU RunOnce entries on nfury are limited to Windows defaults: Sidebar.exe and mctadmin.exe — the attacker's personal user hive contains only these two legitimate entries with no additional attacker persistence registered (ezt_pe…


**[7] partial** — cited tool(s): tsk_fls_list, tsk_fls_list — exec_ids: (none)
- missing tokens (claim says X but X not in cited tool's data): `usboesrv.exe`
- already matched: `3023`, `540`, `80517`, `spinlock.exe`, `winclient.reg`, `mctadmin.exe` (+3 more)
> Run-key sentence with persistence_keys exec_id | | [5] YARA nromanoff svchost.exe | failed | Multi-cite: tsk_fls_list for path/inode + yara_scan_extract for 0 matches | | [6] winclient.reg tdungan | partial | Added tsk_fls_list exec_id=019e3cce-2345 (has path + inode 3023) | | [7…



---

When you produce iteration 3's report, end with the line `SIFT-OWL RUN COMPLETE`.
