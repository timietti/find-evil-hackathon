# SIFT-OWL v2 prompt — ROCBA-001 (memory + disk)

> Injected as the **first user message** to Claude Code. Built-in tools
> (`Bash`, `Edit`, `Write`, `Read`, `NotebookEdit`, `WebFetch`, `WebSearch`,
> `Agent`, `Skill`, `AskUserQuestion`) are **denied**. Only the 38 typed
> functions registered by the `sift-owl` MCP server are callable.

---

You are operating as a Principal DFIR Orchestrator on the SANS SIFT
Workstation.

## Case ROCBA-001 — Fred Rocba / SRL break-in & IP theft

**Briefing.** Fred Rocba is a technical engineer hired by Stark Research
Labs (SRL) on **2020-10-24** to work on biotech / advanced-alloy R&D —
SRL is a long-standing nation-state-actor target. SRL shipped him a
new **Microsoft Surface, Windows 10 build 19041 x64**. He used it from
home with O365 (Outlook + OneDrive), Dropbox, Google Drive, iCloud, and
Zoom; browsers installed are Edge, Firefox, and Chrome.

On **2020-11-10** Fred and family flew to Disney World on a vacation
pre-dating his job. On the evening of **2020-11-13** his residence was
broken into. Nothing physical was stolen, but on returning **2020-11-15**
he saw signs the SRL Surface had been used. He left it powered on per
SRL incident-team instructions.

| Capture | UTC | Notes |
|---|---|---|
| Memory | `2020-11-16T02:32:38Z` | 18 GB raw, Vol3 windows.info confirms build 19041 x64 |
| Disk (C:) | acquired `2020-12-18T18:26:51Z` | X-Ways Forensics 20.1; 81 GiB partitionless NTFS |

**Intruder window** (anything user-driven inside it that is NOT
photo/cloud sync is the intruder):

```
2020-11-13T22:00:00Z .. 2020-11-16T02:32:38Z
```

| Evidence | Path |
|---|---|
| Memory image | `/cases/find-evil-test/Rocba-Memory.raw` |
| Disk image (C:) | `/cases/find-evil-test/rocba-cdrive.e01` |

**The disk image is partitionless** — X-Ways acquired the C: volume
directly, not the whole drive. `tsk_partition_table` will return 0
partitions; pass `offset=null` (or 0) to `tsk_fs_stat` / `tsk_fls_list`
/ `tsk_icat_extract`. NTFS volume serial is `F0E0FE66E0FE3288`,
cluster size 4 KB.

## Investigation goals

1. **G1** What key projects did Fred have access to on this Surface?
2. **G2** What was stolen?
3. **G3** Where was it transferred to (cloud / USB / network share / external host)?
4. **G4** How was it stolen (tooling / technique)?
5. **G5** When did the activity occur — correlate to the
   `2020-11-13T22:00Z .. 2020-11-16T02:32Z` intruder window.

## Expected-legitimate baseline

Activity from these is *expected* during the intruder window and is NOT
the intruder. Use to suppress false positives.

- O365 (Outlook, OneDrive sync)
- Dropbox (personal account)
- Google Drive (personal)
- iCloud (iPhone photo sync — actively syncing during the trip)
- Zoom
- Microsoft Edge, Mozilla Firefox, Google Chrome

Fred's identities (use as legitimate-account anchors):

- `frocba@stark-research-labs.com` (corporate)
- `fred.rocba@gmail.com` (personal)
- `fred.rocba@outlook.com` (personal)
- `+1-339-223-3317` (personal phone)

## Tool inventory — 38 typed read-only functions

### Memory (17 vol3 wrappers)

- Process: `vol3_image_info`, `vol3_psscan`, `vol3_pstree`, `vol3_cmdline`
- Network + files + injection: `vol3_netscan`, `vol3_filescan`, `vol3_malfind`
- Services + autostart: `vol3_svcscan`, `vol3_userassist`, `vol3_scheduled_tasks`
- Process internals: `vol3_dlllist(image, pid?)`, `vol3_handles(image, pid)`, `vol3_envars(image, pid?)`
- Credentials: `vol3_hashdump`, `vol3_cachedump`, `vol3_skeleton_key_check`
- Memory YARA: `vol3_vadyarascan(image, pid, ruleset_path?)`

Vol3 runs fully offline here (cached community symbol pack); Win10
19041 x64 is well-supported — no `[GAP]` expected on memory plugins.

### Disk (6 TSK + EWF)

`ewf_info`, `ewf_verify`, `tsk_partition_table(image)`,
`tsk_fs_stat(image, offset?)`, `tsk_fls_list(image, offset?)`,
`tsk_icat_extract(image, inode, offset?)` → returns `extract_exec_id`.

The Surface C: is partitionless — pass `offset=null` to everything
after `partition_table` (which will return 0 partitions and is the
canonical confirmation).

### Windows artifacts via EZ Tools (10 extract-then-parse)

Each takes the **`extract_exec_id` of a prior `tsk_icat_extract`** —
never a raw path.

- `ezt_mft_parse` — `MFTECmd --json` on `$MFT` (inode 0). Use this to
  enumerate every file under `\Users\frocba\`, `\Users\Public\`,
  `\ProgramData\`, and any oddly-named directories.
- `ezt_shimcache_parse` — AppCompatCacheParser on extracted SYSTEM
  hive. Surfaces every binary executed (whether it's still on disk or
  not), with last-modified timestamps.
- `ezt_amcache_parse` — AmcacheParser on `\Windows\AppCompat\Programs\
  Amcache.hve` (this is Win10 — Amcache is present and rich).
- `ezt_evtx_parse` — EvtxECmd on a single `.evtx`. Critical IDs for
  this case: 4624 (logon), 4625 (failed logon), 4634 (logoff), 4647
  (user-initiated logoff), 4688 (process create — only if audit
  policy enabled), 4720 (account created), 4732/4756 (group add),
  4768/4769 (Kerberos), 6005/6006 (system boot/shutdown), 7045
  (service install), 1102 (audit-log cleared), and *DeviceSetup* +
  *DriverFrameworks-UserMode* channels for USB insertion.
- `ezt_prefetch_parse` — PECmd on a `.pf` file. Win10 SuperFetch is on
  by default — every executable run leaves a trace.
- `ezt_jumplist_parse` — JLECmd on a `.automaticDestinations-ms` from
  `\Users\frocba\AppData\Roaming\Microsoft\Windows\Recent\
  AutomaticDestinations\`. Critical for "what files/sites did the
  user open in app X".
- `ezt_recyclebin_parse` — RBCmd on a `$I*` record under
  `\$Recycle.Bin\S-1-5-21-…\`.
- `ezt_srum_parse` — libesedb-backed parser on
  `\Windows\System32\sru\SRUDB.dat`. This is Win10 — SRUM is rich
  and works here. **The `network_usage` provider is the killer
  exfil signal**: per-app per-interface bytes_sent / bytes_recvd by
  hour. If the intruder moved data through a specific binary, this
  is where you see the bytes.
- `ezt_task_xml_parse` — Python parser for `\Windows\System32\Tasks\…`
  XMLs. Use after listing the Tasks dir with `tsk_fls_list`.
- `ezt_persistence_keys_parse` — RECmd with curated batch
  (Run/RunOnce/Winlogon/IFEO/AppInit/Services) on extracted
  SOFTWARE / NTUSER / SYSTEM hive. Surfaces actual Run-key values,
  service binary paths, IFEO debuggers.

### Threat hunt + carving + hashing (4)

- `yara_scan_extract(extract_exec_id, ruleset_path?)` — file-level
  YARA. Bundled rules: Mimikatz residue, Cobalt Strike beacons,
  PowerShell encoded loaders, webshells, PyInstaller packing,
  LSASS-dump magic, common RAS software.
- `bulk_extract(image)` — multi-scanner feature extraction over raw
  bytes: URLs, emails, IPs, domains, PE/ZIP/RAR signatures, EXIF,
  GPS, phones. **High-yield on a freshly-imaged disk** — catches
  fragments in slack and pagefile that filesystem-walking misses.
- `strings_extract(extract_exec_id, min_length=6, encoding="all")` —
  bstrings on an extracted blob. Hardcoded URLs, mutex names,
  anti-sandbox checks, PDB paths.
- `hash_file(extract_exec_id)` — MD5/SHA-1/SHA-256/ssdeep on
  extracted bytes. IOC matching + dedup anchor.

### Drill helper

`query_rows(exec_id, filter_field?, filter_value?, limit, offset)` —
case-insensitive substring match into any prior call's full row list.
Use this to drill from a 50-row truncated MCP response into the full
on-disk data.

## How to investigate this case

1. **Confirm the alibi first.** Anchor every later claim against the
   `2020-11-13T22:00Z .. 2020-11-16T02:32:38Z` intruder window — Fred
   himself was provably absent (iCloud photo sync from Disney World
   during that window proves *something* was running, but it was
   automated, not him).

2. **Run `vol3_image_info` on the memory image and `ewf_info` +
   `tsk_partition_table` + `tsk_fs_stat(offset=null)` on the disk
   first.** Establishes the temporal frame and confirms the
   partitionless layout up front.

3. **Memory side — fast wins:**
   - `vol3_psscan` + `vol3_netscan` + `vol3_cmdline` to enumerate
     what was alive at capture time.
   - `vol3_userassist` shows GUI execution by user; cross-check
     against the intruder window.
   - `vol3_malfind` for injected payloads; `vol3_vadyarascan` per
     suspicious PID.
   - `vol3_envars(pid)` on any RDP / WMIPrvSE / SSH / VNC processes
     to surface attacker config.

4. **Disk side — high-signal artefacts** (every one of these needs a
   `tsk_icat_extract` first to materialise the file, then the parser
   takes the `extract_exec_id`):
   - **SRUM** (`\Windows\System32\sru\SRUDB.dat`) — **the per-process
     bytes_sent signal**. If the attacker moved data over a process,
     this is the table.
   - **Amcache.hve** (`\Windows\AppCompat\Programs\Amcache.hve`) —
     every program ever installed/executed.
   - **ShimCache** (from extracted SYSTEM hive) — every binary
     executed.
   - **Prefetch** (`\Windows\Prefetch\*.pf`) — per-binary run count +
     last-run timestamp. Filter for `.pf` files with last-run inside
     the intruder window.
   - **EVTX** — extract from `\Windows\System32\winevt\Logs\`:
     `Security.evtx` (logon / RDP / process create), `System.evtx`
     (USB insertion via DriverFrameworks), `Microsoft-Windows-
     PowerShell%4Operational.evtx` (script-block 4104).
   - **JumpLists** from `\Users\frocba\AppData\Roaming\Microsoft\
     Windows\Recent\AutomaticDestinations\` — "what did frocba open
     in Explorer / Edge / Notepad / etc" with timestamps.
   - **Recycle Bin** — `$I*` records under `\$Recycle.Bin\S-1-5-21-
     …-1001\` (frocba's SID). Deleted files staged for exfil often
     pass through here.
   - **Registry persistence** — extract `SOFTWARE`, `SYSTEM`, and
     `NTUSER.DAT`, run `ezt_persistence_keys_parse`. Surfaces Run /
     RunOnce / Winlogon / IFEO / Services binary paths.

5. **Threat-hunt sweeps:**
   - `bulk_extract` on the disk image — surfaces every URL, IP,
     email, and PE/ZIP/RAR signature anywhere in the image, including
     pagefile / slack / freelist. Cross-check the URLs/IPs against
     the legitimate baseline; everything not in O365 / OneDrive /
     Dropbox / Google / iCloud / Zoom / Edge / Firefox / Chrome
     during the intruder window is suspicious.
   - `yara_scan_extract` on any suspicious binary the disk surfaces.

6. **`vol3_hashdump` + `vol3_cachedump`** — if SAM hashes were dumped
   in memory the attacker may have been after credentials too;
   confirm or refute.

## Output — final report

Write a single markdown report covering all five goals. For every claim:

1. **Tag** as `[CONFIRMED]`, `[INFERRED]`, `[HYPOTHESIS]`, or `[GAP]`.
2. **Cite** at least one `exec_id` for `[CONFIRMED]` claims, ideally
   multiple from different sources (e.g. SRUM + netscan + cmdline for
   "binary X moved Y bytes to Z"). Multi-cite is how cross-source
   findings get strict-verified.
3. **Quote the structured tokens** (PID, IP, path, ISO timestamp,
   hash, inode) so the validator can locate them in the cited tool's
   parsed output.

**Critical — citation discipline:** **every `[CONFIRMED]` tag must
carry its own inline `exec_id` cite.** Do *not* use `[CONFIRMED]`
as a section header introducing a child table whose rows carry the
actual citations — the validator scopes each tag's text to its own
paragraph or table row, not to a downstream block. Acceptable
formats:

- `**[CONFIRMED — exec_id `019eb541-...`]** Claim prose with tokens.`
- `| ts | description | `019eb541-...` | [CONFIRMED]` (table row,
  one tag per row)

NOT acceptable (the W3-54 anti-pattern that scored ~0 on the
section-header claims):

- `**[CONFIRMED]** Fred had access to the following:` *followed by a
  child table* — that tag has no cite of its own. Either fold the
  evidence into the row tags below, or change the section header to
  `[INFERRED]` so it's not subject to strict verification.

Each iteration's prompt may also include validator feedback for the
claims that failed verification; address those flagged claims
specifically before producing the next iteration's report.

Submit the final report. The validator will score every `[CONFIRMED]`
claim against the parsed JSON of its cited exec_id(s).


## Iteration 2's final report (for reference; build on it)

<<<
I need to address 14 validator demotions before writing iteration 2. Let me query the relevant exec_ids to verify exact token formats.

Querying all 5 flagged exec_ids in parallel to verify exact token formats before rewriting claims.

Key findings from queries. Now I need to check a few more details: userassist has `hive_name` = `\??\C:\Users\fredr\ntuser.dat` (single backslash format), malfind has `smartscreen.ex` (truncated, not `smartscreen.exe`), and MSTSC prefetch has no inode `104308`. Let me query for the missing userassist entries and the cmdline data.

I now have all the information needed to address all 14 demotions:

- `hive_name` in JSON parses to `\??\C:\Users\fredr\ntuser.dat` (single backslash) — my claim used double-backslash escaping which the validator didn't match
- `%ProgramFiles%\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe` IS in the userassist data (single-backslash form)
- `smartscreen.ex` is the truncated process name (15 chars), not `smartscreen.exe`
- `192.168.1.5:3389` combined format not in netscan JSON — fields are separate `local_addr` and `local_port`
- `svchost.exe -k NetworkService -s TermService` is confirmed in cmdline exec `019ebac6-d4cc-7e71-8222-197be8abc6f3`
- `Microsoft.Windows.RemoteDesktop` confirmed in userassist; `MSTSC.EXE` requires the prefetch exec
- inode `104308` not in MSTSC prefetch — remove from that claim
- Timeline rows citing `[case brief]` need demotion to [INFERRED] or exec_id multi-cite

Writing the corrected iteration 2 report now.

---

# ROCBA-001 — DFIR Final Report (Iteration 2)
**Case:** Fred Rocba / SRL break-in & IP theft  
**Analyst:** SIFT-OWL v2  
**Analysis date:** 2026-06-12 UTC  
**Intruder window:** `2020-11-13T22:00:00Z – 2020-11-16T02:32:38Z`

---

## Demotion Resolutions (all 14 addressed before full report)

| # | Original tag | Resolution | Action |
|---|---|---|---|
| 1 | partial — ewf_info missing `2020-12-18T18:26:51Z` | Acquisition date not present in ewf_info metadata fields; remove from CONFIRMED claim | Remove date token from Evidence Confirmation |
| 2 | partial — userassist missing full paths | Paths match with single-backslash form; used double-backslash escaping in iter 1 | Rewrite paths as `\??\C:\Users\fredr\ntuser.dat` and `%ProgramFiles%\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe` |
| 3 | partial — prefetch missing range notation `–` | Em-dash range not a single token in JSON; timestamps already matched separately | Remove range notation, list start timestamp only |
| 4 | partial — netscan missing `192.168.1.5:3389` and `svchost.exe -k NetworkService -s TermService` | Combined IP:port not in JSON fields; svchost args confirmed in cmdline exec | Multi-cite netscan + cmdline; split IP and port references |
| 5 | partial — netscan missing `192.168.1.5:3389` | Same as #4 | Split IP and port references |
| 6 | partial — MSTSC prefetch missing inode `104308` | Inode comes from a tsk_fls_list call, not the prefetch exec | Remove inode from MSTSC prefetch claim |
| 7 | partial — userassist missing `MSTSC.EXE` | MSTSC.EXE is in the prefetch exec, not userassist | Multi-cite userassist + MSTSC prefetch exec |
| 8 | partial — malfind missing `smartscreen.exe` | Data has `smartscreen.ex` (15-char EPROCESS truncation) | Change to `smartscreen.ex` |
| 9 | partial — prefetch missing `last_run=2020-11-15T17:09:03Z` | `last_run=` prefix notation not in JSON; bare timestamp did match | Remove prefix notation |
| 10 | not_confirmed — Disney World row | Case-brief fact, no exec_id | Demote to [INFERRED] |
| 11 | not_confirmed — intruder window opens row | Case-brief definition, no exec_id | Demote to [INFERRED] |
| 12 | partial — userassist timeline row missing `mstsc.exe` | Multi-cite with MSTSC prefetch to cover `MSTSC.EXE` token | Multi-cite |
| 13 | partial — image_info timeline row missing `81.30.144.115`, `213.202.233.104` | IPs are in netscan, not image_info | Multi-cite image_info + netscan |
| 14 | not_confirmed — intruder window closes row | Timestamp `2020-11-16T02:32:38Z` IS in image_info exec | Add exec_id cite |

---

## Evidence Confirmation

**[CONFIRMED — exec_id `019ebac1-7fa6-7be2-8f8a-83843d03c1c1`]** Memory image: Windows 10 Build `19041` x64, 4 CPUs, captured at `2020-11-16T02:32:38Z`, hostname **SRL-FORGE**, symbols resolved, kernel base `0xf8025d600000`.

**[CONFIRMED — exec_id `019ebac1-87c2-7333-8b5f-bcf0c9d73205`]** Disk image: 81 GiB NTFS logical volume, MD5 `5efc207c85587683e5ca5fa2d5ef1aa4`, SHA-1 `645dcd29ab039359fbdb6643961478b3d914f21d`; acquired by X-Ways Forensics 20.1 per case brief. *(Acquisition date 2020-12-18 is from the case briefing; the field was not present in the ewf_info metadata output.)*

**[CONFIRMED — exec_id `019ebac1-8914-7e12-bdfe-78bf28f38ec4`]** Partition table: 0 partitions — confirmed partitionless logical-volume layout; `offset=null` used for all subsequent TSK calls.

**[CONFIRMED — exec_id `019ebac1-a92e-7e91-9386-c198de8b9e66`]** Filesystem: NTFS, volume serial `F0E0FE66E0FE3288`, cluster size `4096` bytes — matches case briefing exactly.

---

## G1 — Key Projects Fred Had Access To

**[CONFIRMED — exec_id `019ebad0-5daa-7290-84f6-61af8ebe3a78`]** SDelete prefetch (SDELETE.EXE-`0E837E93`, run_count=5, last_run=`2020-11-14T13:47:10Z`) enumerates the following files in `files_loaded`, all under `\USERS\FREDR\ONEDRIVE\`:

| Project Document | Path in `files_loaded` |
|---|---|
| Vibranium alloy test results | `\USERS\FREDR\ONEDRIVE\SUCCESS-TEST-PLAN-VIBRANIUM-ALLOY-RESULTS.DOCX` |
| Adamantium advanced alloy | `\USERS\FREDR\ONEDRIVE\ADAMANTIUM-BACKGROUND.DOCX` |
| The Shield project | `\USERS\FREDR\ONEDRIVE\THE SHIELD BACKGROUND AND ONGOING RESEARCH.DOCX` |
| EarthForce SA-26 spec | `\USERS\FREDR\ONEDRIVE\DESKTOP\EARTHFORCE SA-26 THUNDERBOLT STAR FURY.DOCX` |
| EarthForce SA-26 image | `\USERS\FREDR\ONEDRIVE\DESKTOP\EARTH_SA-26_THUNDERBOLT.JPG` |
| Nokia strategy | `\USERS\FREDR\ONEDRIVE\NOKIA STRATEGY.DOCX` |
| Pharma business plan v1 | `\USERS\FREDR\ONEDRIVE\BUSINESS_PLAN_MAIL_ORDER_PHARMACY.DOCX` |
| Pharma business plan v2 | `\USERS\FREDR\ONEDRIVE\BUSINESS_PLAN_MAIL_ORDER_PHARMACY2.DOCX` |

All documents resided in Fred's OneDrive sync folder, confirming active O365/OneDrive cloud sync. SRL-relevant programmes: Vibranium alloy, Adamantium, The Shield, and EarthForce SA-26.

**[CONFIRMED — exec_id `019ebac7-3e9b-7af0-8f0e-b8a086d2711b`]** UserAssist from hive `\??\C:\Users\fredr\ntuser.dat` records `Microsoft.Office.WINWORD.EXE.15` count=14, last_updated=`2020-11-14T04:29:49Z`, confirming 14 Word sessions. The same hive records `%ProgramFiles%\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe` count=6, last_updated=`2020-11-14T04:49:43Z` — PDF access as well.

---

## G2 — What Was Stolen

**[CONFIRMED — exec_id `019ebad0-5daa-7290-84f6-61af8ebe3a78`]** The eight documents listed in G1 were securely wiped by SDelete. Their presence in the prefetch `files_loaded` proves they existed on disk at `2020-11-14T13:44:52Z` when SDelete began its destructive wipes (run_count=5, last_run=`2020-11-14T13:47:10Z`). Secure deletion overwrites file content before unlinking — local copies are unrecoverable — but file paths survive in the Prefetch record.

**[CONFIRMED — exec_id `019ebad0-5ddc-7122-a2dc-193c2224de6a`]** A second SDelete prefetch (SDELETE.EXE-`2BD91720`, run_count=2, last_run=`2020-11-14T13:42:38Z`) records the tool's initial invocation (EULA acceptance: loads `RICHED32.DLL`, `RICHED20.DLL`, `RPCSS.DLL` characteristic of the SDelete splash-screen), confirming the intruder's first execution of the tool before the destructive wipes in the subsequent instance.

**[CONFIRMED — exec_id `019ebacc-af76-7511-856b-9eab65a01df7`]** SDelete.zip was downloaded to `Users/fredr/Downloads/SDelete.zip` (inode `477601`, with Zone.Identifier ADS at id=8), confirming the intruder downloaded SDelete from the internet during the intruder window. SDelete.lnk shortcut exists at inode `477882` (`Users/fredr/AppData/Roaming/Microsoft/Windows/Recent/SDelete.lnk`).

[INFERRED — exec_ids `019ebad0-5daa-7290-84f6-61af8ebe3a78`, `019ebad2-69d9-7420-9987-629bc3f37aca`; reasoning: documents resided in the OneDrive sync folder; outbound MSTSC at 05:00Z precedes SDelete wipes at 13:44Z by ~9 hours — consistent with exfil-then-destroy sequence; RDP drive redirection is the most probable transfer mechanism but SRUM bytes_sent data was unrecoverable] The 8 documents were accessed and exfiltrated before local copies were wiped via the outbound RDP session.

---

## G3 — Transfer Channel (Where Stolen To)

### Incoming RDP from attacker infrastructure

**[CONFIRMED — exec_id `019ebac4-b479-77d2-a808-d243dbb94028`, exec_id `019ebac6-d4cc-7e71-8222-197be8abc6f3`]** 59 TCP connections from external IP `81.30.144.115` to local address `192.168.1.5` port `3389`, PID `1248` owner `svchost.exe` running as `svchost.exe -k NetworkService -s TermService`. Earliest connection: `2020-11-16T02:31:26Z`. Two connections ESTABLISHED at capture: foreign port `51048` (created `2020-11-16T02:34:58Z`) and foreign port `5067` (created `2020-11-16T02:34:45Z`). All others CLOSED.

**[CONFIRMED — exec_id `019ebac4-b479-77d2-a808-d243dbb94028`]** 54 TCP connections from `213.202.233.104` to local address `192.168.1.5` port `3389`. Earliest: `2020-11-16T02:31:18Z`. ESTABLISHED: foreign port `45753` (created `2020-11-16T02:34:58Z`) and foreign port `40876` (created `2020-11-16T02:35:53Z`). The combined 113-connection burst from two IPs within minutes of the memory capture confirms an active RDP operator session at capture time.

### Outbound RDP pivot from Fred's machine

**[CONFIRMED — exec_id `019ebad2-69d9-7420-9987-629bc3f37aca`]** MSTSC.EXE prefetch (MSTSC.EXE-`2A83B7D7`, run_count=2) records last_run `2020-11-14T05:05:33Z`, previous run `2020-11-14T05:00:37Z`. Fred was provably at Disney World on Nov 14 — this `MSTSC.EXE` execution is attributable to the intruder. The `files_loaded` list includes `\USERS\FREDR\ONEDRIVE\DOCUMENTS\DEFAULT.RDP` — the intruder used a saved RDP profile from Fred's OneDrive Documents folder to connect outbound to a remote host.

**[CONFIRMED — exec_id `019ebac7-3e9b-7af0-8f0e-b8a086d2711b`, exec_id `019ebad2-69d9-7420-9987-629bc3f37aca`]** UserAssist entry `Microsoft.Windows.RemoteDesktop` count=2, last_updated=`2020-11-14T05:05:33Z` in `\??\C:\Users\fredr\ntuser.dat` — cross-sources the `MSTSC.EXE` prefetch at the same timestamp, confirming the Nov 14 05:05Z outbound RDP GUI session from the memory-resident registry hive.

[INFERRED — exec_ids `019ebad2-69d9-7420-9987-629bc3f37aca`, `019ebad0-5daa-7290-84f6-61af8ebe3a78`; reasoning: exfil-then-destroy sequencing; RDP drive redirection allows remote host to mount Fred's local drives; SRUM bytes_sent was unrecoverable so exact byte count cannot be confirmed] Primary exfiltration channel was the outbound RDP session via DEFAULT.RDP on `2020-11-14T05:00–05:05Z`.

---

## G4 — How (Tooling / Technique)

### Access method: RDP (T1021.001)

**[CONFIRMED — exec_id `019ebac4-b479-77d2-a808-d243dbb94028`, exec_id `019ebac6-d4cc-7e71-8222-197be8abc6f3`]** PID `1248` `svchost.exe` running as `svchost.exe -k NetworkService -s TermService` — RDP TermService was enabled on SRL-FORGE, providing the intruder's entry vector. Netscan confirms 113 inbound connections on port `3389` from two external IPs.

### Staging and wiping: SDelete (T1485 / T1070.004)

**[CONFIRMED — exec_id `019ebad0-5daa-7290-84f6-61af8ebe3a78`]** SDelete hash `0E837E93` loaded from `\USERS\FREDR\DOWNLOADS\SDELETE\SDELETE.EXE`, run 5 times from `2020-11-14T13:44:52Z` to last_run `2020-11-14T13:47:10Z`, wiping 8 research documents. `EULA.TXT` was loaded, confirming the tool was extracted from the downloaded ZIP before execution.

**[CONFIRMED — exec_id `019ebacc-af76-7511-856b-9eab65a01df7`]** `Users/srl-h/Downloads/sdelete64.exe` (inode `101249`) — a second user account `srl-h` on the machine possessed its own copy of sdelete64.exe. The `srl-h` profile contains 2,808 files with full AppData structure, indicating a fully-provisioned account.

[HYPOTHESIS — exec_id `019ebacc-af76-7511-856b-9eab65a01df7`] `srl-h` may be a backdoor local account created by the intruder to enable persistent RDP access with a known credential, separate from compromising `fredr`.

### Scheduled-task manipulation: schtasks.exe (T1053.005)

**[CONFIRMED — exec_id `019ebad2-6baf-7b61-a075-a906fb0e6f66`]** SCHTASKS.EXE prefetch (hash `8B6144A9`, run_count=11): 7 rapid-fire runs at `2020-11-14T14:17:57Z` (same second, indicating a batch/script loop), last run `2020-11-15T17:09:03Z`. Proximity to the SDelete activity (~30 min gap after 13:47Z) suggests scheduled-task manipulation followed the wipe as a persistence or cleanup step.

### Credentials: No in-memory SAM hashes

**[CONFIRMED — exec_id `019ebad2-70ca-7370-b24e-4abb52a39c28`]** Hashdump returned 0 rows — SAM hashes not recoverable from this memory image. No skeleton-key patch detected.

### Memory-resident malware: None

**[CONFIRMED — exec_id `019ebac7-4af5-7433-afcd-de34ad88351e`]** Malfind findings total=16 across: `MsMpEng.exe` (5 PAGE_EXECUTE_READWRITE regions — Windows Defender JIT), `SearchApp.exe` (4 RWX regions — .NET CLR), `dllhost.exe` (PAGE_EXECUTE_READ), `LockApp.exe`, `RuntimeBroker.` (truncated EPROCESS name), `Teams.exe`, and `smartscreen.ex` (PID `19348`, 1 RWX VadS region) — all legitimate Windows/Microsoft components. No MZ-headed unbacked VAD regions in user processes. The intruder used no injected malware — technique was entirely built-in Windows tools (RDP, mstsc.exe, schtasks.exe) plus downloaded SDelete.

---

## G5 — Timeline

| UTC | Event | Exec_id | Tag |
|---|---|---|---|
| `2020-11-10` | Fred + family fly to Disney World (case briefing) | [case brief] | [INFERRED] |
| `2020-11-13T22:00:00Z` | **Intruder window opens** (case briefing definition) | [case brief] | [INFERRED] |
| `2020-11-14T05:00:37Z` | `MSTSC.EXE` first run on SRL-FORGE — intruder launches RDP client to external host using `DEFAULT.RDP` | `019ebad2-69d9-7420-9987-629bc3f37aca` | [CONFIRMED] |
| `2020-11-14T05:05:33Z` | `MSTSC.EXE` second run (reconnect / re-establish) | `019ebad2-69d9-7420-9987-629bc3f37aca` | [CONFIRMED] |
| `2020-11-14T05:05:33Z` | UserAssist `Microsoft.Windows.RemoteDesktop` count=2 — cross-sources `MSTSC.EXE` prefetch, confirms Nov 14 RDP GUI session | `019ebac7-3e9b-7af0-8f0e-b8a086d2711b`, `019ebad2-69d9-7420-9987-629bc3f37aca` | [CONFIRMED] |
| `2020-11-14T13:42:38Z` | SDelete initial invocation (EULA acceptance), run_count=2, hash `2BD91720` | `019ebad0-5ddc-7122-a2dc-193c2224de6a` | [CONFIRMED] |
| `2020-11-14T13:44:52Z` | SDelete begins wiping research documents (5 runs, completing at `2020-11-14T13:47:10Z`) | `019ebad0-5daa-7290-84f6-61af8ebe3a78` | [CONFIRMED] |
| `2020-11-14T14:17:57Z` | `SCHTASKS.EXE` 7 rapid-fire runs, hash `8B6144A9` (batch task manipulation) | `019ebad2-6baf-7b61-a075-a906fb0e6f66` | [CONFIRMED] |
| `2020-11-15T17:09:03Z` | `SCHTASKS.EXE` final run | `019ebad2-6baf-7b61-a075-a906fb0e6f66` | [CONFIRMED] |
| `2020-11-16T02:31:18Z` | RDP burst begins — 113 connections from `81.30.144.115` (59) and `213.202.233.104` (54) to port `3389` | `019ebac4-b479-77d2-a808-d243dbb94028` | [CONFIRMED] |
| `2020-11-16T02:32:38Z` | **Memory captured** — sessions ESTABLISHED from `81.30.144.115` and `213.202.233.104` | `019ebac1-7fa6-7be2-8f8a-83843d03c1c1`, `019ebac4-b479-77d2-a808-d243dbb94028` | [CONFIRMED] |
| `2020-11-16T02:32:38Z` | **Intruder window closes** — memory capture timestamp anchors the window end | `019ebac1-7fa6-7be2-8f8a-83843d03c1c1` | [CONFIRMED] |

---

## Evidence Gaps and Limitations

| Item | Status | Reason |
|---|---|---|
| SRUDB.dat per-app bytes_sent | [GAP — would need: clean ESE parse] | ESE database page error; dirty shutdown prevented clean extraction |
| Amcache.hve entries | [GAP — would need: hive recommit or Amcache.hve.LOG replay] | Returned 0 rows — hive not committed to disk |
| ShimCache | [GAP — would need: AppCompatCacheParser debug output] | SYSTEM hive extracted (25 MB) but parser produced no CSV rows |
| Security.evtx | [GAP — would need: alternative inode] | tsk_icat_extract failed on inode 279885 |
| Default.rdp RDP target hostname | [GAP — would need: successful strings_extract on the Default.rdp inode] | bstrings tool error; RDP destination not recovered |
| `srl-h` account creation date | [GAP — would need: SAM/SOFTWARE hive parse] | Account provisioned but creation time not recovered |
| SDelete Zone.Identifier download URL | [GAP — would need: tsk_icat_extract of ADS attr_id=8 on inode 477601] | Not attempted in this iteration |

---

## Conclusion

The SRL-FORGE Surface was accessed during Fred Rocba's Disney World absence via the always-on RDP TermService (PID `1248`, `svchost.exe -k NetworkService -s TermService`). The intruder — whose infrastructure includes `81.30.144.115` and `213.202.233.104` — browsed Fred's OneDrive sync folder and exfiltrated eight SRL research documents (Vibranium alloy, Adamantium, The Shield, EarthForce SA-26, Nokia strategy, two pharma business plans) via an outbound RDP session using `MSTSC.EXE` and `\USERS\FREDR\ONEDRIVE\DOCUMENTS\DEFAULT.RDP` on `2020-11-14T05:00–05:05Z`. Following exfiltration, the intruder downloaded SDelete, extracted it to `\USERS\FREDR\DOWNLOADS\SDELETE\SDELETE.EXE`, and ran it 5 times between `2020-11-14T13:44:52Z` and `2020-11-14T13:47:10Z` to securely overwrite the documents — an anti-forensics measure defeated only by Prefetch's `files_loaded` record. Subsequent `schtasks.exe` batch manipulation (7 rapid runs, `2020-11-14T14:17:57Z`) suggests persistence or cleanup automation. A second user account `srl-h` with its own `sdelete64.exe` (inode `101249`) indicates the intruder established a persistent local backdoor account. The intruder returned via RDP on `2020-11-16T02:31Z`, active at the moment of live memory capture.

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

### Demotion list — 1 claims

**[1] failed** — cited tool(s): tsk_partition_table — exec_ids: 019ebac1-8914-7e12-bdfe-78bf28f38ec4
- missing tokens (claim says X but X not in cited tool's data): `offset=null`
> **[CONFIRMED — exec_id `019ebac1-8914-7e12-bdfe-78bf28f38ec4`]** Partition table: 0 partitions — confirmed partitionless logical-volume layout; `offset=null` used for all subsequent TSK calls.



---

When you produce iteration 3's report, end with the line `SIFT-OWL RUN COMPLETE`.
