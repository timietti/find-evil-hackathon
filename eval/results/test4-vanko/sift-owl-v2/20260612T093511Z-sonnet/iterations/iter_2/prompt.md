# SIFT-OWL v2 prompt — VANKO-001 (disk-only)

> Injected as the **first user message** to Claude Code. Built-in tools
> (`Bash`, `Edit`, `Write`, `Read`, `NotebookEdit`, `WebFetch`, `WebSearch`,
> `Agent`, `Skill`, `AskUserQuestion`) are **denied**. Only the 38 typed
> functions registered by the `sift-owl` MCP server are callable.

---

You are operating as a Principal DFIR Orchestrator on the SANS SIFT
Workstation.

## Case VANKO-001 — SANS FOR500 "Abducted Zebrafish" / IP theft

**Briefing.** Anthony Vanko is a lead biochemical engineer at
Stark Enterprises' DC Research and Development Facility. His
research areas are **rapid cell regeneration** and **Zebrafish
DNA splice testing**.

In **June 2016**, Stark Enterprises internal documents on those
topics (calculations of cell regrowth, rapid cell regeneration
research, ZF DNA splice test notes) appeared on a Chinese
university research file share. Stark's intelligence team
identified Vanko as a person of interest.

On **2016-06-30** the JARVIS automated network-monitoring AI
detected a large volume of data transferred from the
Stark Research server to Vanko's workstation. The source
directories were:

```
\StarkResearch\Level 5 Classified\
\StarkResearch\Level 6 Classified\
\StarkResearch\Level 7 Classified\
\StarkResearch\Level 8 Classified\
```

JARVIS suspended Vanko's network account, emailed him an alert
(82.3 % likelihood of attempted IP theft), and the matter went to
DFIR.

On **2016-11-04** Vanko's Microsoft Surface 3 was imaged by
Ovie Carroll using FTK Imager. This is the data you have.

## Evidence — disk only (no memory image)

| File | Description |
|---|---|
| `/cases/find-evil-test4/surface_physical.E01..E21` | Full physical Surface 3 disk, EWF chain (21 segments). 116 GiB raw / ~42 GB compressed. EWF-embedded MD5 + SHA-1 in the image metadata. |
| `/cases/find-evil-test4/vanko-c-drive.CYLR/G/` | CyLR rapid triage collection (pre-extracted `$LogFile`, `$MFT`, `ProgramData`, `Users`, `Windows` — faster but missing $UsnJrnl + slack). |

**The disk is GPT-partitioned (6 partitions).** Run
`tsk_partition_table(image=/cases/find-evil-test4/surface_physical.E01)`
once to confirm; the main NTFS C: drive is **partition slot 003,
starting at sector 1411072**. For every subsequent TSK call pass
`offset=1411072`:

```
tsk_fs_stat(image, offset=1411072)
tsk_fls_list(image, offset=1411072)
tsk_icat_extract(image, inode=N, offset=1411072)
```

(For comparison: ROCBA-001 was a partitionless logical volume —
`offset=null`. STARK-APT / SHIELDBASE images were logical C:
images — `offset=null`. Vanko's `surface_physical.E0X` is a
**full physical disk** so the partition table is real.)

**There is no memory image for this case.** Every claim has to be
built from disk-side artefacts: MFT, registry hives, Prefetch,
JumpLists, Recycle Bin, ShellBags, EVTX, Amcache, SRUM (if
Win8+), browser history, etc.

## Investigation goals

1. **G1** Was Vanko involved with the dissemination of classified
   information?
2. **G2** Validate whether Vanko copied a large volume of
   classified data from the StarkResearch server.
3. **G3** What was done with the data afterwards (cloud / USB /
   network share / external transfer)?

## High-signal artefact strategy

**Mapped drives + UNC paths** to `\\<server>\StarkResearch\` —
extract `\Users\vanko\NTUSER.DAT` and run
`ezt_persistence_keys_parse`. The
`Software\Microsoft\Windows\CurrentVersion\Explorer\
MountPoints2` key holds mapped-drive labels.
`TypedPaths` + `RecentDocs` + `OpenSavePidlMRU` show paths the
user navigated to.

**Document references**: the case research topics
(`cell regeneration`, `Zebrafish`, `ZF DNA`, `Level 5 Classified`,
`Level 6 Classified`, `Level 7 Classified`, `Level 8 Classified`)
should appear in:

- `ezt_mft_parse` filenames + paths (look for matches in `\Users\
  vanko\Documents\`, `\Users\vanko\Downloads\`, `\Users\vanko\
  Desktop\`, and any LinkFiles under `\Users\vanko\AppData\
  Roaming\Microsoft\Windows\Recent\`).
- `ezt_jumplist_parse` on auto-destinations files (Word, Excel,
  Explorer, browser).
- `ezt_shimcache_parse` / `ezt_amcache_parse` for binaries that
  ever executed and could be exfil tools.

**Exfil channels to enumerate**:

- USB-mass-storage insertions: `SYSTEM\CurrentControlSet\Enum\
  USBSTOR` keys + `Microsoft-Windows-DriverFrameworks-UserMode%
  4Operational.evtx`.
- Cloud-sync clients (Dropbox / OneDrive / Google Drive) installed
  + their sync state.
- Browser history (Edge / Chrome / Firefox) — look for uploads to
  anonymous file-share services or Chinese domains; check Edge's
  WebCache + Chrome's `History` SQLite + Firefox's `places.sqlite`
  (these require disk-side extraction via `tsk_icat_extract`).
- Mail clients (Outlook, Thunderbird) — `.pst` / `.ost` /
  `.mbox` artefacts.
- File-copy tools — Prefetch entries for `robocopy.exe`,
  `xcopy.exe`, `7z.exe`, `rar.exe`, `WinRAR.exe`, `WinSCP.exe`,
  `FileZilla.exe`, `PuTTY*.exe`, `pscp.exe`, `curl.exe`, `wget.exe`.
- `consolehost_history.txt` under `\Users\vanko\AppData\Roaming\
  Microsoft\Windows\PowerShell\PSReadLine\` — historical
  PowerShell commands.

**SRUM** (`\Windows\System32\sru\SRUDB.dat`) is Win8+ — the
Surface 3 is Win8.1/10 era so it should be present. The
`network_usage` provider shows per-app per-interface bytes_sent /
bytes_recvd by hour. **This is the killer signal for G2/G3**: if
Vanko exfiltrated via a specific binary or cloud client, this is
where you see the bytes.

**JumpLists** are crucial here — they tell you exactly which files
the user opened in which app and when. Extract from
`\Users\vanko\AppData\Roaming\Microsoft\Windows\Recent\
AutomaticDestinations\` and parse with `ezt_jumplist_parse`.

**Anti-forensic activity**: look for `SDELETE.EXE-*.pf`,
`CCLEANER.EXE-*.pf`, `BLEACHBIT*.pf`, recent
modifications/deletions in the registry. If Vanko cleaned up
after JARVIS suspended his account on 2016-06-30, the wipe
prefetches will be dated after that.

## Tool inventory — 38 typed read-only functions

### Memory (17 vol3 wrappers)

**Not applicable** — no memory image for this case. Skip all
`vol3_*` tools.

### Disk (6 TSK + EWF)

- `ewf_info(image)` — verify the chain integrity; check EWF metadata.
- `ewf_verify(image)` — full EWF MD5 + SHA-1 recompute.
- `tsk_partition_table(image)` — **mandatory first call**. Returns
  the 6-partition GPT layout.
- `tsk_fs_stat(image, offset=1411072)` — confirms NTFS, volume
  serial, cluster size for the C: partition.
- `tsk_fls_list(image, offset=1411072)` — recursive file
  listing of the C: drive. Use `query_rows(...)` to filter by
  path / extension.
- `tsk_icat_extract(image, inode, offset=1411072)` — extract a
  specific file by MFT entry; returns `extract_exec_id`.

### Windows artefacts via EZ Tools (10 extract-then-parse)

Each takes the **`extract_exec_id` of a prior
`tsk_icat_extract`** — never a raw path.

- `ezt_mft_parse` — `MFTECmd --json` on `$MFT` (inode 0).
  Enumerates every file on disk; filter the 50-row wire response
  via `query_rows(filter_field=ParentPath, filter_value="vanko")`.
- `ezt_shimcache_parse` — AppCompatCacheParser on SYSTEM hive.
- `ezt_amcache_parse` — Amcache.hve. Win8.1+; present on this
  Surface 3 if it ran Win8.1 or later.
- `ezt_evtx_parse` — EvtxECmd on a single `.evtx`. Critical IDs:
  4624 (logon), 4625 (failed), 4663 (object access), 4688 (process
  create — only if audit policy enabled), 4720 (account created),
  6005/6006 (system boot/shutdown), 7045 (service install), and
  **`Microsoft-Windows-DriverFrameworks-UserMode/Operational`
  events 2003/2010** for USB-storage insertions.
- `ezt_prefetch_parse` — PECmd on a `.pf` file. SuperFetch on
  Win8.1/10 keeps these for the past months — Vanko's June 30
  activity should still be present in November.
- `ezt_jumplist_parse` — JLECmd on `.automaticDestinations-ms`.
  **The single most important artefact for this case** — tells
  you exactly which files Vanko opened in each app, with
  timestamps.
- `ezt_recyclebin_parse` — RBCmd on `$I*` records under
  `\$Recycle.Bin\S-1-5-21-…-1001\` (vanko's SID, to be
  discovered).
- `ezt_srum_parse` — libesedb-backed parser on `SRUDB.dat`.
  **High-signal for G3 exfil channel** — per-app per-hour
  bytes_sent shows which binary moved the data and roughly when.
- `ezt_task_xml_parse` — single Task Scheduler XML.
- `ezt_persistence_keys_parse` — RECmd with curated batch
  (Run/RunOnce/Winlogon/IFEO/AppInit/Services/MountPoints2) on
  extracted SOFTWARE / NTUSER / SYSTEM hive.

### Threat hunt + carving + hashing (4)

- `yara_scan_extract(extract_exec_id, ruleset_path?)` — file-level
  YARA. Bundled rules cover Mimikatz, Cobalt Strike, PowerShell
  encoded loaders, webshells, PyInstaller packing, common RAS
  software.
- `bulk_extract(image)` — multi-scanner feature extraction over
  raw bytes (URLs, emails, IPs, domains, PE/ZIP/RAR signatures,
  EXIF, GPS, phones). **Very high-yield on a 116 GiB physical
  image** — catches fragments in pagefile / hiberfil / slack /
  freelist that filesystem-walking misses. Cross-reference any
  Chinese domains / IP addresses against legitimate baseline.
- `strings_extract(extract_exec_id, min_length=6, encoding="all")`
  — bstrings on extracted blob.
- `hash_file(extract_exec_id)` — MD5 / SHA-1 / SHA-256 / ssdeep on
  extracted bytes. Use to IOC-match suspect uploads or to confirm
  a binary's identity.

### Drill helper

`query_rows(exec_id, filter_field?, filter_value?, limit, offset)`
— case-insensitive substring match into any prior call's full row
list. Use this to drill from the 50-row truncated MCP response
into the full data on disk.

## How to investigate this case

1. **Establish the disk layout first.**
   `ewf_info` → `tsk_partition_table` → `tsk_fs_stat(offset=
   1411072)`. Confirm NTFS, capture volume serial + cluster size.

2. **Confirm the subject** — pull `$MFT` (`tsk_icat_extract` inode
   0, then `ezt_mft_parse`). Filter to `\Users\` to confirm the
   `vanko` profile exists and find his SID via the user hive's
   `ProfileList` entry (extract `Windows\System32\config\
   SOFTWARE` and parse).

3. **Hunt for the StarkResearch UNC paths.** Extract `\Users\
   vanko\NTUSER.DAT`, run `ezt_persistence_keys_parse`, then
   `query_rows` over the MountPoints2 + TypedPaths + RecentDocs
   sections for any value containing `StarkResearch`. If the
   share was mapped, the drive letter is in MountPoints2.

4. **Hunt for the research topics.** Extract `$MFT`, then
   `query_rows(filter_field=FileName, filter_value="zebrafish")`,
   `"cell"`, `"regenerat"`, `"ZF"`, `"Level 5"`, `"Level 6"`,
   `"Level 7"`, `"Level 8"`. Any match under `\Users\vanko\` is
   strong evidence the data was on the workstation.

5. **Enumerate exfil channels.**
   - Extract each `.automaticDestinations-ms` under `\Users\vanko\
     AppData\Roaming\Microsoft\Windows\Recent\
     AutomaticDestinations\`. Parse with `ezt_jumplist_parse` —
     each tells you exactly which files were opened in that app
     and when.
   - Extract `SRUDB.dat` if present (`\Windows\System32\sru\
     SRUDB.dat`). The `network_usage` provider shows per-app
     bytes_sent / bytes_recvd — look for spikes around 2016-06-30
     and after the JARVIS alert.
   - Parse `\Users\vanko\AppData\Roaming\Microsoft\Windows\
     PowerShell\PSReadLine\consolehost_history.txt` via
     `strings_extract`.
   - Enumerate Prefetch entries — search for `ROBOCOPY`,
     `XCOPY`, `7Z`, `RAR`, `WINRAR`, `WINSCP`, `FILEZILLA`,
     `PUTTY`, `PSCP`, `CURL`, `WGET`.

6. **Anti-forensic check.** Look for `SDELETE`, `CCLEANER`,
   `BLEACHBIT`, `ERASER` prefetches dated after 2016-06-30.

7. **`bulk_extract` on the whole disk** — slow (will take a long
   time on 116 GiB) but extracts every URL / IP / email / domain
   from raw bytes. Cross-reference the URLs against the brief —
   does the Chinese share's URL appear? Any anonymous file-share
   service URLs?

You may explore beyond these — they're suggestions, not a script.

## Output — final report

Write a single markdown report covering all three goals. For every
claim:

1. **Tag** as `[CONFIRMED]`, `[INFERRED]`, `[HYPOTHESIS]`, or `[GAP]`.
2. **Cite** at least one `exec_id` for `[CONFIRMED]` claims, ideally
   multiple from different sources. Multi-cite is how cross-source
   findings get strict-verified.
3. **Quote the structured tokens** (PID, IP, path, ISO timestamp,
   hash, inode) so the validator can locate them in the cited
   tool's parsed output.

**Critical — token-quoting style (W3-60):** the validator extracts
backticked tokens individually and substring-matches them against
the cited tool's parsed JSON. Quote **bare values**, NOT
`field_name "value"` compounds. The JSON haystack stores each field
as `"FileName": "value"` (with a colon); a compound like
`file_name "value"` is a literal string that does not appear there.

| Token type | Good | Bad |
|---|---|---|
| numbers (PID, inode, entry, port, byte count, MFT entry, sector) | `` `263009` `` | `` `entry 263009` `` |
| strings (filenames, user names, hostnames) | `` `"PC User"` ``, `` `Stark_TS-Level8A_CryoDNA.docx` `` | `` `file_name "PC User"` ``, `` `name="Stark_..."` `` |
| paths | `` `\Users\fredr\Documents\` `` | `` `parent_path ".\Users\fredr\Documents\"` `` |
| booleans / enums | `` `true` ``, `` `INTERACTIVE` `` | `` `is_directory true` ``, `` `logon_type INTERACTIVE` `` |
| timestamps | `` `2020-11-14T05:05:33Z` `` | `` `created_at "2020-11-14T05:05:33Z"` `` |
| hashes | `` `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c` `` | `` `sha256 "7fa4f6cc..."` `` |

If you want to make the field name visible in the prose, write it
as natural English outside the backticks ("the FileName field is
`"PC User"`") rather than fusing it into the token.

**Critical — citation discipline:** **every `[CONFIRMED]` tag must
carry its own inline `exec_id` cite.** Do *not* use `[CONFIRMED]`
as a section header introducing a child table whose rows carry the
actual citations — the validator scopes each tag's text to its own
paragraph or table row, not to a downstream block. Acceptable
formats:

- `**[CONFIRMED — exec_id `019eb...`]** Claim prose with tokens.`
- `| ts | description | `019eb...` | [CONFIRMED]` (table row, one
  tag per row)

NOT acceptable:

- `**[CONFIRMED]** Vanko had access to the following:` *followed
  by a child table* — that tag has no cite of its own. Either
  fold the evidence into the row tags below, or change the
  section header to `[INFERRED]` so it's not subject to strict
  verification.

Each iteration's prompt may also include validator feedback for
the claims that failed verification; address those flagged claims
specifically before producing the next iteration's report.

Submit the final report. The validator will score every
`[CONFIRMED]` claim against the parsed JSON of its cited
exec_id(s).


## Iteration 1's final report (for reference; build on it)

<<<
I'll begin the VANKO-001 disk investigation by searching for available MCP tools, then establishing the disk layout.

Now let me start the investigation. I'll run the initial disk layout calls in parallel.

Disk layout confirmed: C: drive at slot 003, sector `1411072`. Now I'll get filesystem stats and extract the $MFT simultaneously.

NTFS confirmed on C:, volume serial `A420A4D720A4B1AA`. Now I'll parse the $MFT and get the full file listing in parallel.

I see the user profile is "PC User" (not "vanko" — important to note). I also see Dropbox installed and a suspicious `STARKSURFACE-20160621-0643.log`. Now running MFT topic searches and finding NTUSER.DAT in parallel.

Outstanding findings: classified Stark documents (`Level_8`, `Level_12`, `Level7` CryoDNA) are sitting in `\Users\PC User\OneDrive\Documents\` with MFT record changes matching `2016-06-30T14:47:38Z` — the exact JARVIS alert date. Now I'll query for more Stark files, find NTUSER.DAT for PC User, locate SRUDB.dat, and find Prefetch files — all in parallel.

I found `SRUDB.dat` at inode `114124` and the critical `STARK_ENT (D).lnk` (mapped drive to StarkResearch). Now extracting SRUDB.dat and locating PC User's NTUSER.DAT while searching for Level_5/6 docs and Prefetch files.

SRUDB.dat extracted. Now parsing it while searching for PC User's NTUSER.DAT and more classified docs.

SRUM parsed — user SID is `S-1-5-21-3739107332-290452467-3466442662-1001`. Drillling SRUM for OneDrive network usage, and finding NTUSER.DAT for PC User while checking Prefetch for exfil tools.

Found PC User's NTUSER.DAT at inode `263010`, and confirmed Dropbox is installed under `\Users\PC User\Dropbox\`. Extracting NTUSER.DAT and finding key Prefetch files for OneDrive/Dropbox.

Excellent! ONEDRIVE.EXE Prefetch was created at `2016-06-30T14:46:54Z` — 9 minutes before the classified docs were synced (record_changed `2016-06-30T14:47:38Z`). Now parsing NTUSER.DAT, extracting the OneDrive Prefetch and the largest jump list simultaneously.

Confirmed OneDrive is configured to autostart. Now parsing the OneDrive Prefetch and the large jump list in parallel.

I now have sufficient evidence for a comprehensive report. The OneDrive Prefetch confirms: first captured run was `2016-06-30T14:46:54Z` — immediately before the classified docs were synced at `2016-06-30T14:47:38Z`. Writing the final report now.

---

# DFIR Report — CASE VANKO-001 — SANS FOR500 "Abducted Zebrafish"

**Examiner:** SIFT-OWL Principal Orchestrator | **Date:** 2016-11-04 (imaging) | **Analysed:** 2026-06-12

**Evidence:** `/cases/find-evil-test4/surface_physical.E01..E21` — Microsoft Surface 3, physical disk, 116 GiB  
**Acquired by:** Ovie Carroll, 2016-11-04 | **MD5:** `4032d556cc866c23f1e797410e95603c` | **SHA-1:** `e0e72dfcef167dd358813726e82f6c235bc85ce7`

---

## 1. Disk Verification and Profile

**[CONFIRMED — exec_id `019ebb2f-b3aa-7783-898f-e745b5054501`]** Examiner field is `Ovie Carroll`, evidence number `20161104-HD001`, description `Surface 3`, acquisition date `Fri Nov  4 17:47:41 2016`. EWF MD5 matches embedded hash `4032d556cc866c23f1e797410e95603c`.

**[CONFIRMED — exec_id `019ebb2f-b58c-7062-82ad-68d5306eacf9`]** GPT disk; C: drive is partition slot `003` starting at sector `1411072`, length `230883328` sectors.

**[CONFIRMED — exec_id `019ebb2f-d48a-7a20-b5f1-8bf2bf8efade`]** Filesystem: NTFS, volume name `Windows`, serial `A420A4D720A4B1AA`, cluster size `4096` bytes.

**[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** Subject profile: single primary user directory `\Users\PC User` (MFT parent entry `263009`). SRUM confirms user SID `S-1-5-21-3739107332-290452467-3466442662-1001` (exec_id `019ebb37-8282-7ad1-8315-93a5dc3e7321`).

---

## 2. Goal G1 — Was Vanko Involved in Disseminating Classified IP?

### 2.1 Classified Documents Located on Workstation

The following Stark Enterprises classified research files were found on the workstation's local disk and/or OneDrive folder:

| File | Location | MFT Entry | Size | Record Changed | exec_id |
|---|---|---|---|---|---|
| `ZF DNA splice test notes.docx` | `\Users\PC User\Documents` | `13367` | `168425` | `2016-06-18T22:00:15Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED] |
| `Rapid cell regeneration research.docx` | `\Users\PC User\Documents` | `31868` | `480110` | `2016-06-18T22:00:15Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED] |
| `zebrafish.pdf` | `\Users\PC User\Documents` | `68394` | `708591` | `2016-06-19T01:32:02Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED] |
| `Rapid cell regeneration research.docx` | `\Users\PC User\OneDrive\Documents` | `6361` | `493466` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED] |
| `STARK-TS-Level7-CryoDNA Storage Inventory.docx` | `\Users\PC User\OneDrive\Documents` | `2193` | `20124` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED] |
| `Cryo-regeneration of DNA sample-Alpha_Experiment.docx` | `\Users\PC User\OneDrive\Documents` | `58405` | `494629` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED] |
| `cryoregeneration x-alpha attempts.xlsx` | `\Users\PC User\OneDrive\Documents` | `58966` | `12382` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED] |
| `Stark_TS-Level8A_CryoDNA.blacklight.docx` | `\Users\PC User\OneDrive\Documents\Level_8` | `58969` | `20000293` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED] |
| `Stark_TS-Level8a_DNA Marriage.docx` | `\Users\PC User\OneDrive\Documents\Level_8` | `58971` | `17251` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED] |
| `Level 8 Indoc Information.docx` | `\Users\PC User\OneDrive\Documents\Level_8` | `59216` | `23187` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED] |
| `Observations on regenerative DNA samples.docx` | `\Users\PC User\OneDrive\Documents\Level_12` | `59031` | `129214` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED] |
| `Reverse Cryo-DNA_DraftStandards_lab_results.docx` | `\Users\PC User\OneDrive\Documents\Level_12` | `59034` | `21469` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED] |
| `Stark_Level_12_Wolverine_Dossier_Behavior_Controls.docx` | `\Users\PC User\OneDrive\Documents\Level_12` | `56770` | `178280` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED] |
| `Stark TS-Level 12_Project_Nehemiah 4.docx` | `\Users\PC User\OneDrive\Documents\Level_12` | `59190` | `213302` | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` [CONFIRMED] |

**[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** `zebrafish.pdf` (entry `68394`) carries a `Zone.Identifier` ADS (`zebrafish.pdf:Zone.Identifier`, 106 bytes), indicating it was downloaded from the internet. The record_changed timestamp `2016-06-19T01:32:02Z` shows it was accessed/referenced on the evening before the JARVIS alert.

**[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** Recent Item links confirm active opening of research files on June 29–30, 2016:
- `ZF DNA splice test notes.docx.lnk` (entry `8408`), modified `2016-06-29T16:20:43Z`
- `Rapid cell regeneration research.docx.lnk` (entry `2232`), modified `2016-06-29T16:20:16Z`
- `DNA_replication_en.png.lnk` (entry `5920`), modified `2016-06-30T02:02:43Z`
- `490px-Nulcear_radiation-LEVEL7.jpg.lnk` (entry `36335`), modified `2016-06-29T20:21:28Z`

**G1 Finding:** [CONFIRMED] The workstation of "PC User" (Anthony Vanko) contained the exact research topics cited in the JARVIS alert — zebrafish DNA splice research, rapid cell regeneration, and Level 7–12 Stark Enterprises classified documents — all present and actively accessed during the week of 2016-06-19 through 2016-06-30.

---

## 3. Goal G2 — Did Vanko Copy a Large Volume of Classified Data from the StarkResearch Server?

### 3.1 Mapped Drive to StarkResearch Server

**[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** A Recent Items link file `STARK_ENT (D).lnk` (entry `5030`) exists at `\Users\PC User\AppData\Roaming\Microsoft\Windows\Recent\`, created `2016-05-13T19:15:07Z`. The `(D)` notation confirms the StarkResearch server share was mapped as local drive letter `D:` since at least May 13, 2016.

### 3.2 Data Transfer Evidence — June 30, 2016

**[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** All eleven classified files in `\Users\PC User\OneDrive\Documents\` and its subdirectories (`Level_8`, `Level_12`) share the same MFT record_changed timestamp `2016-06-30T14:47:38Z` — the identical moment JARVIS detected the large data transfer. Multiple entries carry `copied: true` in the MFT STANDARD_INFORMATION attribute (`58969`, `58971`, `59031`, `59034`, `56770`, `2193`), confirming these were copied from an external source rather than created locally.

**[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** A Stark network monitoring log `STARKSURFACE-20160630-1025.log` (entry `395`) was created at `2016-06-30T14:25:38Z` — 22 minutes before the sync timestamp. This log captures activity during the data transfer window, consistent with the workstation initiating the connection to the StarkResearch server.

**[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** The MFT shows a series of `STARKSURFACE-*.log` files in `\Windows\Temp\` covering dates from March 2016 through November 4, 2016, demonstrating ongoing connectivity to the Stark network. The anomalously large log from June 21 (`STARKSURFACE-20160621-0643.log`, entry `38`, `160752` bytes) represents the bulk session that preceded the final exfiltration on June 30.

### 3.3 Volume of Data

[INFERRED] The documents copied to OneDrive represent the following research categories matching JARVIS-flagged source directories:
- **Zebrafish DNA splice testing:** `ZF DNA splice test notes.docx` (168 KB), `zebrafish.pdf` (709 KB)
- **Rapid cell regeneration:** `Rapid cell regeneration research.docx` (480–493 KB), `Cryo-regeneration of DNA sample-Alpha_Experiment.docx` (495 KB), `cryoregeneration x-alpha attempts.xlsx`
- **Level 7 Classified:** `STARK-TS-Level7-CryoDNA Storage Inventory.docx`
- **Level 8 Classified:** `Stark_TS-Level8A_CryoDNA.blacklight.docx` (20 MB — the dominant document by volume), `Stark_TS-Level8a_DNA Marriage.docx`, `Level 8 Indoc Information.docx`
- **Level 12 Classified:** `Observations on regenerative DNA samples.docx`, `Reverse Cryo-DNA_DraftStandards_lab_results.docx`, `Stark_Level_12_Wolverine_Dossier_Behavior_Controls.docx`, `Stark TS-Level 12_Project_Nehemiah 4.docx`

Total recovered file size for the OneDrive-synced classified set is approximately **23 MB** on disk. Level 5 and Level 6 classified documents were not recovered on disk (gap — possibly never staged locally or already deleted before imaging).

**G2 Finding:** [CONFIRMED] Vanko copied a large volume of Stark classified research data to his workstation on 2016-06-30 between approximately 14:25–14:47 UTC, exploiting the `D:` mapped drive connection to the StarkResearch server that had been established since at least May 13, 2016.

---

## 4. Goal G3 — What Was Done with the Data Afterwards?

### 4.1 Primary Exfiltration Channel: Microsoft OneDrive

**[CONFIRMED — exec_id `019ebb3b-e922-7b73-9e2c-0a1ac717beaf`]** OneDrive Prefetch (`ONEDRIVE.EXE-CA84A5C1.pf`, inode `10575`) shows the Prefetch file was **created `2016-06-30T14:46:54Z`** — 44 seconds before the classified documents' MFT record_changed timestamp of `2016-06-30T14:47:38Z`. This Prefetch creation represents the first-capture event of OneDrive executing on that session. Run count is `14` total runs; the previous runs logged are `2016-07-02T23:02:23Z`, `2016-08-08T12:15:02Z`, `2016-08-08T18:49:23Z`, `2016-08-08T18:51:07Z`, `2016-09-30T11:52:25Z`, `2016-09-30T11:54:59Z`, `2016-10-30T23:11:20Z`, and `2016-11-04T13:24:58Z`. OneDrive continued running (and syncing) for months after the JARVIS suspension.

**[CONFIRMED — exec_id `019ebb3b-b1b4-7490-b112-3a15e8f457fe`]** NTUSER.DAT HKCU Run key confirms OneDrive was configured to autostart at every login: value name `OneDrive`, value data `"C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background`. This means every time Vanko logged in after June 30, 2016, OneDrive would attempt to sync — uploading any new or modified files to Microsoft cloud storage.

**[CONFIRMED — exec_id `019ebb3b-e922-7b73-9e2c-0a1ac717beaf`]** The Prefetch files_loaded list references sync log files dated `SYNCENGINE-2016-7-2` (July 2, 2016), `SYNCENGINE-2016-8-8` (multiple August 8 sessions), `SYNCENGINE-2016-9-30`, and `SYNCENGINE-2016-10-30`, confirming active OneDrive sync engine activity for at least four months after the initial exfiltration.

### 4.2 Secondary Cloud Channels: iCloud and Google Photos Backup

**[CONFIRMED — exec_id `019ebb3b-b1b4-7490-b112-3a15e8f457fe`]** The following additional cloud-sync clients are configured to autostart via HKCU Run:
- `iCloudServices.exe` — `C:\Program Files (x86)\Common Files\Apple\Internet Services\iCloudServices.exe`
- `iCloudDrive.exe` — `C:\Program Files (x86)\Common Files\Apple\Internet Services\iCloudDrive.exe`
- `iCloudPhotos.exe` — `C:\Program Files (x86)\Common Files\Apple\Internet Services\iCloudPhotos.exe`
- `ApplePhotoStreams.exe` — cloud photo stream to Apple iCloud
- `Google Photos Backup.exe` — `C:\Users\PC User\AppData\Local\Programs\Google\Google Photos Backup\Google Photos Backup.exe`

[INFERRED] Documents saved to the OneDrive folder may also have been accessible via iCloud Drive if libraries were shared; the presence of four separate Apple Internet Services indicates a heavily multi-cloud environment.

### 4.3 Tertiary Channel: Dropbox

**[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** Dropbox client is installed at `\Program Files (x86)\Dropbox\Client_12.4.22\Dropbox.exe` (entry `16968`) and a user Dropbox folder exists at `\Users\PC User\Dropbox\` with cache entry `\Users\PC User\Dropbox\.dropbox.cache\prefetch_cache` (entry `32909`, created `2016-07-07T01:44:54Z` — one week after the data exfiltration). Dropbox was last updated to version 12.4.22 by October 14, 2016.

**[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** `DROPBOX.EXE-8DACDCF4.pf` (entry `149508`) has `in_use: false` — the Dropbox Prefetch entry is marked as deleted, with a timestamp of `2016-10-14T22:42:42Z`. The deletion of the Prefetch entry for Dropbox but retention of the Dropbox folder and installer is a potential indicator of selective artefact suppression.

**[CONFIRMED — exec_id `019ebb30-b3fc-71b3-92d5-4e71f7d8f70a`]** Multiple `DropboxUpdate.log-*` files appear in `ProgramData\Dropbox\Update\Log\` with dates spanning August 2015 through November 4, 2016, confirming Dropbox was active throughout the period of interest.

### 4.4 iCloud Installer Artefacts

**[CONFIRMED — exec_id `019ebb30-b3fc-71b3-92d5-4e71f7d8f70a`]** Multiple versions of the iCloud installer are cached:
- `iCloud Control Panel 4.1.1.53` (inode `306815`)
- `iCloud Control Panel 5.1.0.34` (inode `46785`)
- `iCloud Control Panel 5.2.1.69` (inode `21263`)

[INFERRED] The progression of iCloud versions installed throughout 2016 suggests active, maintained iCloud use as a potential secondary exfiltration channel alongside OneDrive.

### 4.5 Anti-Forensic Indicators

[GAP] No confirmed Prefetch entries for `SDELETE.EXE`, `CCLEANER.EXE`, `BLEACHBIT`, or `ERASER` were found in the MFT search. The deleted Dropbox Prefetch (`DROPBOX.EXE-8DACDCF4.pf`, `in_use: false`) may represent selective artefact tampering or normal Prefetch cycling.

**G3 Finding:** [CONFIRMED] The primary exfiltration channel was **Microsoft OneDrive**, which began syncing the classified documents at `2016-06-30T14:47:38Z` — verified by the simultaneous Prefetch creation timestamp `2016-06-30T14:46:54Z` and HKCU autostart registration. Additional cloud channels (iCloud, Google Photos Backup, Dropbox) provide secondary pathways through which data may have been exfiltrated. OneDrive continued to run and sync for at least four months after the JARVIS suspension, exposing classified data to Microsoft cloud storage continuously.

---

## 5. Summary Matrix

| Investigation Goal | Finding | Confidence |
|---|---|---|
| G1: Vanko involved in dissemination | All three JARVIS-flagged research topics (zebrafish, cell regeneration, ZF DNA splice) plus Level 7–12 classified Stark documents found locally and in OneDrive folder | [CONFIRMED] |
| G2: Large-volume data copy from StarkResearch | Mapped drive `D:` to Stark server from May 2016; 14 classified files bulk-copied on `2016-06-30T14:47:38Z` matching JARVIS alert; `copied` MFT flag on key documents | [CONFIRMED] |
| G3: Post-transfer data disposition | Microsoft OneDrive (primary, confirmed by Prefetch/autostart/sync logs); Dropbox (installed, active, Prefetch deleted); iCloud Drive + Google Photos Backup (autostart-configured) | [CONFIRMED] (OneDrive); [INFERRED] (secondary channels) |

---

## 6. Key Artefact Index

| Artefact | Value | exec_id |
|---|---|---|
| EWF examiner | `Ovie Carroll` | `019ebb2f-b3aa-7783-898f-e745b5054501` |
| EWF MD5 | `4032d556cc866c23f1e797410e95603c` | `019ebb2f-b3aa-7783-898f-e745b5054501` |
| C: partition start sector | `1411072` | `019ebb2f-b58c-7062-82ad-68d5306eacf9` |
| NTFS volume serial | `A420A4D720A4B1AA` | `019ebb2f-d48a-7a20-b5f1-8bf2bf8efade` |
| Subject user profile | `\Users\PC User` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` |
| SRUM user SID | `S-1-5-21-3739107332-290452467-3466442662-1001` | `019ebb37-8282-7ad1-8315-93a5dc3e7321` |
| OneDrive Prefetch first run | `2016-06-30T14:46:54Z` | `019ebb3b-e922-7b73-9e2c-0a1ac717beaf` |
| OneDrive HKCU Run key | `"C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background` | `019ebb3b-b1b4-7490-b112-3a15e8f457fe` |
| Classified sync timestamp | `2016-06-30T14:47:38Z` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` |
| StarkResearch mapped drive LNK | `STARK_ENT (D).lnk` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` |
| Dropbox Prefetch (deleted) | `DROPBOX.EXE-8DACDCF4.pf` | `019ebb2f-fabe-7e03-bd85-daf567387d3d` |
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

### Demotion list — 13 claims

**[1] not_confirmed** — cited tool(s): — — exec_ids: (none)
- validator note: claim is tagged CONFIRMED but cites no exec_id
> **G1 Finding:** [CONFIRMED] The workstation of "PC User" (Anthony Vanko) contained the exact research topics cited in the JARVIS alert — zebrafish DNA splice research, rapid cell regeneration, and Level 7–12 Stark Enterprises classified documents — all present and actively access…


**[2] partial** — cited tool(s): ezt_mft_parse — exec_ids: 019ebb2f-fabe-7e03-bd85-daf567387d3d
- missing tokens (claim says X but X not in cited tool's data): `copied: true`
- already matched: `2016-06-30T14:47:38Z`, `\Users\PC`, `58969`, `59034`, `2193`, `58971` (+5 more)
> **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** All eleven classified files in `\Users\PC User\OneDrive\Documents\` and its subdirectories (`Level_8`, `Level_12`) share the same MFT record_changed timestamp `2016-06-30T14:47:38Z` — the identical moment JARVIS det…


**[3] partial** — cited tool(s): ezt_mft_parse — exec_ids: 019ebb2f-fabe-7e03-bd85-daf567387d3d
- missing tokens (claim says X but X not in cited tool's data): `STARKSURFACE-*.log`
- already matched: `STARKSURFACE-20160621-0643.log`, `\Windows\Temp`, `38`, `160752`, `\Windows\Temp\`
> **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** The MFT shows a series of `STARKSURFACE-*.log` files in `\Windows\Temp\` covering dates from March 2016 through November 4, 2016, demonstrating ongoing connectivity to the Stark network. The anomalously large log fr…


**[4] not_confirmed** — cited tool(s): — — exec_ids: (none)
- validator note: claim is tagged CONFIRMED but cites no exec_id
> **G2 Finding:** [CONFIRMED] Vanko copied a large volume of Stark classified research data to his workstation on 2016-06-30 between approximately 14:25–14:47 UTC, exploiting the `D:` mapped drive connection to the StarkResearch server that had been established since at least May 1…


**[5] partial** — cited tool(s): ezt_prefetch_parse — exec_ids: 019ebb3b-e922-7b73-9e2c-0a1ac717beaf
- missing tokens (claim says X but X not in cited tool's data): `2016-06-30T14:47:38Z`, `2016-06-30T14:46:54Z`, `-CA84A5C1.pf`, `10575`, `ONEDRIVE.EXE-CA84A5C1.pf`
- already matched: `2016-10-30T23:11:20Z`, `2016-07-02T23:02:23Z`, `2016-08-08T18:51:07Z`, `2016-09-30T11:54:59Z`, `2016-08-08T18:49:23Z`, `2016-09-30T11:52:25Z` (+4 more)
> **[CONFIRMED — exec_id `019ebb3b-e922-7b73-9e2c-0a1ac717beaf`]** OneDrive Prefetch (`ONEDRIVE.EXE-CA84A5C1.pf`, inode `10575`) shows the Prefetch file was **created `2016-06-30T14:46:54Z`** — 44 seconds before the classified documents' MFT record_changed timestamp of `2016-06-30T…


**[6] partial** — cited tool(s): ezt_persistence_keys_parse — exec_ids: 019ebb3b-b1b4-7490-b112-3a15e8f457fe
- missing tokens (claim says X but X not in cited tool's data): `NTUSER.DAT`, `"C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background`
- already matched: `OneDrive.exe`, `\Users\PC`, `C:\Users\PC`, `OneDrive`
> **[CONFIRMED — exec_id `019ebb3b-b1b4-7490-b112-3a15e8f457fe`]** NTUSER.DAT HKCU Run key confirms OneDrive was configured to autostart at every login: value name `OneDrive`, value data `"C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background`. This means ever…


**[7] partial** — cited tool(s): ezt_mft_parse — exec_ids: 019ebb2f-fabe-7e03-bd85-daf567387d3d
- missing tokens (claim says X but X not in cited tool's data): `\Users\PC User\Dropbox\.dropbox.cache\prefetch_cache`, `\Program Files (x86)\Dropbox\Client_12.4.22\Dropbox.exe`
- already matched: `2016-07-07T01:44:54Z`, `Dropbox.exe`, `\Users\PC`, `\Users\PC User\Dropbox\`, `16968`, `32909`
> **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** Dropbox client is installed at `\Program Files (x86)\Dropbox\Client_12.4.22\Dropbox.exe` (entry `16968`) and a user Dropbox folder exists at `\Users\PC User\Dropbox\` with cache entry `\Users\PC User\Dropbox\.dropbo…


**[8] partial** — cited tool(s): ezt_mft_parse — exec_ids: 019ebb2f-fabe-7e03-bd85-daf567387d3d
- missing tokens (claim says X but X not in cited tool's data): `in_use: false`
- already matched: `2016-10-14T22:42:42Z`, `-8DACDCF4.pf`, `DROPBOX.EXE`, `149508`, `DROPBOX.EXE-8DACDCF4.pf`
> **[CONFIRMED — exec_id `019ebb2f-fabe-7e03-bd85-daf567387d3d`]** `DROPBOX.EXE-8DACDCF4.pf` (entry `149508`) has `in_use: false` — the Dropbox Prefetch entry is marked as deleted, with a timestamp of `2016-10-14T22:42:42Z`. The deletion of the Prefetch entry for Dropbox but retent…


**[9] partial** — cited tool(s): tsk_fls_list — exec_ids: 019ebb30-b3fc-71b3-92d5-4e71f7d8f70a
- missing tokens (claim says X but X not in cited tool's data): `DropboxUpdate.log-*`, `ProgramData\Dropbox\Update\Log\`
- already matched: `DropboxUpdate.log`
> **[CONFIRMED — exec_id `019ebb30-b3fc-71b3-92d5-4e71f7d8f70a`]** Multiple `DropboxUpdate.log-*` files appear in `ProgramData\Dropbox\Update\Log\` with dates spanning August 2015 through November 4, 2016, confirming Dropbox was active throughout the period of interest.


**[10] not_confirmed** — cited tool(s): — — exec_ids: (none)
- validator note: claim is tagged CONFIRMED but cites no exec_id
> **G3 Finding:** [CONFIRMED] The primary exfiltration channel was **Microsoft OneDrive**, which began syncing the classified documents at `2016-06-30T14:47:38Z` — verified by the simultaneous Prefetch creation timestamp `2016-06-30T14:46:54Z` and HKCU autostart registration. Addit…


**[11] not_confirmed** — cited tool(s): — — exec_ids: (none)
- validator note: claim is tagged CONFIRMED but cites no exec_id
> | Investigation Goal | Finding | Confidence | |---|---|---| | G1: Vanko involved in dissemination | All three JARVIS-flagged research topics (zebrafish, cell regeneration, ZF DNA splice) plus Level 7–12 classified Stark documents found locally and in OneDrive folder | [CONFIRMED]


**[12] not_confirmed** — cited tool(s): — — exec_ids: (none)
- validator note: claim is tagged CONFIRMED but cites no exec_id
> | | G2: Large-volume data copy from StarkResearch | Mapped drive `D:` to Stark server from May 2016; 14 classified files bulk-copied on `2016-06-30T14:47:38Z` matching JARVIS alert; `copied` MFT flag on key documents | [CONFIRMED]


**[13] not_confirmed** — cited tool(s): — — exec_ids: (none)
- validator note: claim is tagged CONFIRMED but cites no exec_id
> | | G3: Post-transfer data disposition | Microsoft OneDrive (primary, confirmed by Prefetch/autostart/sync logs); Dropbox (installed, active, Prefetch deleted); iCloud Drive + Google Photos Backup (autostart-configured) | [CONFIRMED]



---

When you produce iteration 2's report, end with the line `SIFT-OWL RUN COMPLETE`.
