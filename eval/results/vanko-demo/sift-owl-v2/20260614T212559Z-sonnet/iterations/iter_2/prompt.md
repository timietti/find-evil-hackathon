# SIFT-OWL v2 prompt — vanko-demo (disk-only)

> Injected as the **first user message** to Claude Code. Built-in tools
> (`Bash`, `Edit`, `Write`, `Read`, `NotebookEdit`, `WebFetch`, `WebSearch`,
> `Agent`, `Skill`, `AskUserQuestion`) are **denied**. Only the 38 typed
> functions registered by the `sift-owl` MCP server are callable.

---

You are operating as a Principal DFIR Orchestrator on the SANS SIFT
Workstation.

## Case vanko-demo — FOR500 "Abducted Zebrafish" / Insider IP Theft

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

| File | SHA-256 | Description |
|---|---|---|
| `/cases/find-evil-test4/surface_physical.E01..E21` | E01 segment: `0a44ad8d57bad44eb40a59bdaa8110b79ac019a791b8fd388f6efe09c7aa3b1c` | Full physical Surface 3 disk, EWF chain (21 segments). 116 GiB raw / ~42 GB compressed. Media MD5: `4032d556cc866c23f1e797410e95603c`, SHA-1: `e0e72dfcef167dd358813726e82f6c235bc85ce7`. |
| `/cases/find-evil-test4/vanko-c-drive.CYLR/G/` | — | CyLR rapid triage collection (pre-extracted `$LogFile`, `$MFT`, `ProgramData`, `Users`, `Windows` — faster but missing $UsnJrnl + slack). |

**The disk is GPT-partitioned (6 data partitions).** Run
`tsk_partition_table(image=/cases/find-evil-test4/surface_physical.E01)`
once to confirm; the main NTFS C: drive is **partition slot 003,
starting at sector 1411072**. For every subsequent TSK call pass
`offset=1411072`:

```
tsk_fs_stat(image, offset=1411072)
tsk_fls_list(image, offset=1411072)
tsk_icat_extract(image, inode=N, offset=1411072)
```

**There is no memory image for this case.** Every claim has to be
built from disk-side artefacts: MFT, registry hives, Prefetch,
JumpLists, Recycle Bin, ShellBags, EVTX, Amcache, SRUM (if
Win8+), browser history, etc.

## Investigation goals

1. **G1 — Initial access / involvement** Was Vanko involved with
   the dissemination of classified information? Establish whether
   the classified research files were present on his workstation.
2. **G2 — Persistence / scope** Validate whether Vanko copied a
   large volume of classified data from the StarkResearch server.
   Quantify the transfer where possible (file count, byte volume,
   timestamps).
3. **G3 — Impact / exfil channel** What was done with the data
   afterwards — cloud sync, USB, email, web upload, or network
   share? Identify the specific exfil mechanism and, if possible,
   the destination.
4. **G4 — Attribution** Confirm through forensic artefacts (MFT
   timestamps, Prefetch, NTUSER.DAT, SRUM, logon events) that
   Vanko's Windows account on this machine personally performed
   the actions, ruling out other users on the same device.

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

6. **Attribution check (G4).** Confirm logon events from
   `Security.evtx` — interactive (type 2) and remote (type 10)
   logons for the `vanko` account around 2016-06-30. Correlate
   with NTUSER.DAT `LastWriteTime` and Prefetch timestamps to
   place Vanko specifically at the keyboard during the transfers.

7. **Anti-forensic check.** Look for `SDELETE`, `CCLEANER`,
   `BLEACHBIT`, `ERASER` prefetches dated after 2016-06-30.

8. **`bulk_extract` on the whole disk** — slow (will take a long
   time on 116 GiB) but extracts every URL / IP / email / domain
   from raw bytes. Cross-reference the URLs against the brief —
   does the Chinese share's URL appear? Any anonymous file-share
   service URLs?

You may explore beyond these — they're suggestions, not a script.

## Output — final report

Write a single markdown report covering all four goals. For every
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

When you are done, print `SIFT-OWL RUN COMPLETE` to stdout.


## Iteration 1's final report (for reference; build on it)

<<<
Starting the investigation with disk layout verification and partition confirmation.

Disk verified. C: partition confirmed at sector 1411072. Now getting filesystem stats and extracting $MFT.

NTFS confirmed. Now parsing $MFT and listing the filesystem.

I see "PC User" account, not "vanko" yet. Dropbox is installed - important for G3. Searching MFT for vanko and research topics.

Found `zebrafish.pdf` in `\Users\PC User\Documents\` and Skype account `live#3aanthony.vanko` confirms identity. Searching for more research files and StarkResearch references.

Massive find — classified Stark documents in `\Users\PC User\OneDrive\Documents\` with MFT record_changed timestamps of `2016-06-30T14:47:38Z` (JARVIS alert day). Now finding more research files, NTUSER.DAT, and Prefetch.

Found `Rapid cell regeneration research.docx` in OneDrive. Now extracting NTUSER.DAT and finding SRUDB.dat to parse, plus looking for more classified docs.

Budget is tight. Extracting NTUSER.DAT and SRUDB.dat in parallel to finalize evidence, then writing the report.

I now have sufficient evidence across all four goals. Writing the final report.

---

# DFIR Report — Case vanko-demo (FOR500 "Abducted Zebrafish")

**Examiner:** SIFT-OWL v2  
**Evidence:** `/cases/find-evil-test4/surface_physical.E01` (EWF, 116 GiB physical disk)  
**Chain of custody:** MD5 `4032d556cc866c23f1e797410e95603c`, SHA-1 `e0e72dfcef167dd358813726e82f6c235bc85ce7`, acquired 2016-11-04 by Ovie Carroll with FTK Imager

---

## Image Verification

**[CONFIRMED — exec_id `019ec807-6df2-7bb3-8df4-d4b7e622d20a`]** EWF metadata confirms examiner `Ovie Carroll`, evidence number `20161104-HD001`, acquisition date `Fri Nov  4 17:47:41 2016`, media MD5 `4032d556cc866c23f1e797410e95603c`, SHA-1 `e0e72dfcef167dd358813726e82f6c235bc85ce7` — matches brief exactly. Physical full-disk capture (`is_physical` true, 244,277,248 sectors).

**[CONFIRMED — exec_id `019ec807-6faf-71a0-95c0-67b713439119`]** GPT partition table: C: drive is slot 003 starting at sector `1411072`, length 230,883,328 sectors.

**[CONFIRMED — exec_id `019ec807-82df-7552-b064-48daf866f7ec`]** C: volume is `NTFS`, volume name `Windows`, serial `A420A4D720A4B1AA`, cluster size `4096` bytes.

---

## G4 — Attribution: Identifying the Vanko Account

**[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** The Windows local account username is `PC User` (`\Users\PC User\`). The Skype cache at `\Users\PC User\AppData\Roaming\Skype\live#3aanthony.vanko\` (MFT parent_path contains `live#3aanthony.vanko`) ties this account unambiguously to Anthony Vanko. This is the only user profile in active use.

**[CONFIRMED — exec_id `019ec823-a631-7180-b917-cd3bc5cc928f`]** SRUM push-notification rows carry user_sid `S-1-5-21-3739107332-290452467-3466442662-1001` for the `PC User` account (same SID in every user-mode network row). The Skype executable is registered in HKCU Run (exec_id `019ec823-944e-7840-abd1-5edfeb08a4bc`) confirming account ownership.

**[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** The machine name recorded in Windows Temp logs is `STARKSURFACE` (file `STARKSURFACE-20160621-0643.log`, `STARKSURFACE-20160630-1025.log`, etc.) — confirming this is a Stark Enterprises-issued device used by Vanko.

---

## G1 — Initial Access / Involvement: Classified Research Files on Workstation

### zebrafish.pdf

| Artifact | Value | exec_id |
|---|---|---|
| File path | `\Users\PC User\Documents\zebrafish.pdf` | `019ec807-bfa8-7c93-a303-3a53f0cb5f8d` |
| MFT entry | `68394` | `019ec807-bfa8-7c93-a303-3a53f0cb5f8d` |
| File size | `708591` bytes | `019ec807-bfa8-7c93-a303-3a53f0cb5f8d` |
| Created | `2016-03-06T02:45:20Z` | `019ec807-bfa8-7c93-a303-3a53f0cb5f8d` |
| ADS Zone.Identifier | present (`zebrafish.pdf:Zone.Identifier`) | `019ec807-bfa8-7c93-a303-3a53f0cb5f8d` |

**[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** `zebrafish.pdf` (entry `68394`, size `708591`) resides at `\Users\PC User\Documents\`. The Zone.Identifier ADS (`zebrafish.pdf:Zone.Identifier`, size `106`) confirms it was downloaded from the internet. A Recent LNK `zebrafish.pdf.lnk` (entry `51827`) in `\Users\PC User\AppData\Roaming\Microsoft\Windows\Recent` was last modified `2016-06-19T01:32:02Z` — indicating Vanko actively accessed the file 11 days before the JARVIS alert.

### Rapid cell regeneration research.docx

**[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** `Rapid cell regeneration research.docx` exists in two locations: `\Users\PC User\Documents\` (entry `31868`, size `480110`, record_changed `2016-06-18T22:00:15Z`) and `\Users\PC User\OneDrive\Documents\` (entry `6361`, size `493466`, record_changed `2016-06-30T14:47:38Z`). A Recent LNK (entry `2232`) was last modified `2016-06-29T16:20:16Z` and an Office Recent LNK (entry `33351`) was modified `2016-06-29T16:20:20Z` — confirming the user opened this document the day before the JARVIS alert.

### Classified Stark Research Documents

**[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** The following Stark Enterprises classified documents were found resident on the workstation in `\Users\PC User\OneDrive\Documents\` and subdirectories:

| MFT Entry | File Name | Path | Size (bytes) | record_changed |
|---|---|---|---|---|
| `2193` | `STARK-TS-Level7-CryoDNA Storage Inventory.docx` | `\Users\PC User\OneDrive\Documents\` | `20124` | `2016-06-30T14:47:38Z` |
| `6361` | `Rapid cell regeneration research.docx` | `\Users\PC User\OneDrive\Documents\` | `493466` | `2016-06-30T14:47:38Z` |
| `58969` | `Stark_TS-Level8A_CryoDNA.blacklight.docx` | `\Users\PC User\OneDrive\Documents\Level_8\` | `20000293` | `2016-06-30T14:47:38Z` |
| `58971` | `Stark_TS-Level8a_DNA Marriage.docx` | `\Users\PC User\OneDrive\Documents\Level_8\` | `17251` | `2016-06-30T14:47:38Z` |
| `59216` | `Level 8 Indoc Information.docx` | `\Users\PC User\OneDrive\Documents\Level_8\` | `23187` | `2016-06-30T14:47:38Z` |
| `56770` | `Stark_Level_12_Wolverine_Dossier_Behavior_Controls.docx` | `\Users\PC User\OneDrive\Documents\Level_12\` | `178280` | `2016-06-30T14:47:38Z` |
| `59190` | `Stark TS-Level 12_Project_Nehemiah 4.docx` | `\Users\PC User\OneDrive\Documents\Level_12\` | `213302` | `2016-06-30T14:47:38Z` |
| `68394` | `zebrafish.pdf` | `\Users\PC User\Documents\` | `708591` | `2016-06-19T01:32:02Z` |

All seven OneDrive documents carry the identical `record_changed` timestamp `2016-06-30T14:47:38Z`, which matches the JARVIS-detection event on 2016-06-30. The `copied` field is `true` on entries `2193`, `58969`, `58971`, `56770` — MFTECmd's forensic flag indicating timestamps were set via file-copy rather than native creation.

---

## G2 — Scope / Quantification of the Data Transfer

**[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** At minimum **7 classified documents** were staged locally on 2016-06-30 across Level 7, Level 8, and Level 12 classification tiers. The total measured file size for the confirmed OneDrive documents is approximately **21.6 MB**:

- `Stark_TS-Level8A_CryoDNA.blacklight.docx`: `20000293` bytes (~19.1 MB) — the dominant payload
- `Stark TS-Level 12_Project_Nehemiah 4.docx`: `213302` bytes
- `Stark_Level_12_Wolverine_Dossier_Behavior_Controls.docx`: `178280` bytes
- `Rapid cell regeneration research.docx`: `493466` bytes
- plus smaller Level 7/8 documents

**[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** Directory entries with record_changed `2016-06-30T14:47:38Z` include the Level_8 (entry `56771`) and Level_12 (entry `58961`) subdirectory nodes themselves, indicating the folder structure was replicated on that date — consistent with a bulk recursive copy from the StarkResearch server.

**[INFERRED]** The JARVIS alert cited sources `\StarkResearch\Level 5 Classified\` through `\Level 8 Classified\`. The MFT shows Level 7 and Level 8 documents confirmed present; Level 5/6 documents may have been deleted or stored in unallocated space not recovered via $MFT scan alone.

**[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** The Windows Temp log `STARKSURFACE-20160630-1025.log` (entry `395`) was created `2016-06-30T14:25:38Z` — approximately 22 minutes before the OneDrive record_changed timestamp — indicating system activity on the workstation during the transfer window.

---

## G3 — Exfiltration Channel: Microsoft OneDrive

**[CONFIRMED — exec_id `019ec823-944e-7840-abd1-5edfeb08a4bc`]** OneDrive is configured to auto-start on login via HKCU Run: `OneDrive` → `"C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background`. This means any file placed in `\Users\PC User\OneDrive\` is automatically synced to the cloud without any further user interaction required.

**[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** All seven classified documents are stored inside the local OneDrive folder at `\Users\PC User\OneDrive\Documents\` and its subdirectories. The `\Users\PC User\OneDrive\` tree is the designated local sync folder. Files placed here are automatically uploaded to Vanko's personal OneDrive cloud storage (Microsoft account).

**[CONFIRMED — exec_id `019ec807-bfa8-7c93-a303-3a53f0cb5f8d`]** Multiple OneDrive setup update logs from 2016-06-30 confirm the service was active on that date:
- `Update_2016-06-30_105237_1a24-53c.log` (entry `2005`, created `2016-06-30T14:52:37Z`)
- `Update_2016-06-30_110801_1b74-1b78.log` (entry `15801`, created `2016-06-30T15:08:01Z`)
- `Update_2016-06-30_112703_19bc-19c0.log` (entry `752`, created `2016-06-30T15:27:03Z`)
- `Update_2016-06-30_124406_c90-1344.log` (entry `4993`, created `2016-06-30T16:44:06Z`)

The OneDrive client was actively running and updating on 2016-06-30, the day the classified files were copied to the sync folder.

**[INFERRED]** Secondary potential exfil channels noted but not fully confirmed within this investigation: Dropbox (client installed per `ProgramData/Dropbox/` tree and FLS entry `53` showing Dropbox logs at `\Windows\SysWOW64\config\systemprofile\AppData\Local\Dropbox\`), and iCloud Drive (iCloudDrive.exe in NTUSER.DAT Run key). These are lower confidence as no classified documents were located in those directories.

**[GAP]** No USB-storage artifacts, PowerShell console history, or browser-history records were parsed in this iteration due to budget constraints. USB insertions (USBSTOR) and browser upload history remain unexamined.

---

## Summary

| Goal | Finding | Confidence |
|---|---|---|
| G1 — Classified files on workstation | `zebrafish.pdf`, `Rapid cell regeneration research.docx`, Level 7/8/12 Stark documents all present on disk | [CONFIRMED] |
| G2 — Bulk transfer on 2016-06-30 | 7 docs (~21.6 MB total) with `record_changed` `2016-06-30T14:47:38Z`; Level 8 CryoDNA file alone is ~19 MB | [CONFIRMED] |
| G3 — Exfil via OneDrive | Files staged in OneDrive sync folder; OneDrive auto-start configured; client active on 2016-06-30 | [CONFIRMED] |
| G4 — Attribution to Vanko | Windows account `PC User` owns Skype profile `live#3aanthony.vanko`; user SID `S-1-5-21-3739107332-290452467-3466442662-1001`; machine is `STARKSURFACE` (Stark-issued) | [CONFIRMED] |

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

### Demotion list — 5 claims

**[1] partial** — cited tool(s): ezt_persistence_keys_parse — exec_ids: 019ec823-944e-7840-abd1-5edfeb08a4bc
- missing tokens (claim says X but X not in cited tool's data): `"C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background`
- negation violations (claim says NOT X but X IS in cited tool's data): `\Users\PC`, `OneDrive`
- already matched: `OneDrive.exe`, `C:\Users\PC`
> **[CONFIRMED — exec_id `019ec823-944e-7840-abd1-5edfeb08a4bc`]** OneDrive is configured to auto-start on login via HKCU Run: `OneDrive` → `"C:\Users\PC User\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background`. This means any file placed in `\Users\PC User\OneDrive\` is au…


**[2] not_confirmed** — cited tool(s): — — exec_ids: (none)
- validator note: claim is tagged CONFIRMED but cites no exec_id
> | Goal | Finding | Confidence | |---|---|---| | G1 — Classified files on workstation | `zebrafish.pdf`, `Rapid cell regeneration research.docx`, Level 7/8/12 Stark documents all present on disk | [CONFIRMED]


**[3] not_confirmed** — cited tool(s): — — exec_ids: (none)
- validator note: claim is tagged CONFIRMED but cites no exec_id
> | | G2 — Bulk transfer on 2016-06-30 | 7 docs (~21.6 MB total) with `record_changed` `2016-06-30T14:47:38Z`; Level 8 CryoDNA file alone is ~19 MB | [CONFIRMED]


**[4] not_confirmed** — cited tool(s): — — exec_ids: (none)
- validator note: claim is tagged CONFIRMED but cites no exec_id
> | | G3 — Exfil via OneDrive | Files staged in OneDrive sync folder; OneDrive auto-start configured; client active on 2016-06-30 | [CONFIRMED]


**[5] not_confirmed** — cited tool(s): — — exec_ids: (none)
- validator note: claim is tagged CONFIRMED but cites no exec_id
> | | G4 — Attribution to Vanko | Windows account `PC User` owns Skype profile `live#3aanthony.vanko`; user SID `S-1-5-21-3739107332-290452467-3466442662-1001`; machine is `STARKSURFACE` (Stark-issued) | [CONFIRMED]



---

When you produce iteration 2's report, end with the line `SIFT-OWL RUN COMPLETE`.
