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


## Iteration 2's final report (for reference; build on it)

<<<
I'll systematically address all 14 demoted claims by querying the prior execution data to find missing tokens or determine correct demotions. Starting by loading tools and querying the key exec_ids.

Querying previous exec_ids in parallel to resolve all 14 demotion issues.

The field names may differ. Let me check the actual MFT row structure and query with different filters.

Good — now I see the field names are lowercase (`parent_path`, `file_name`). Re-querying with correct field names.

Found key data. Now querying specific MFT entries to verify the flags for claims [3], [4], [8], and check 7ZFM.EXE.

Good. Now checking 7ZFM.EXE entry and the volume serial exec_id in parallel.

I now have all the data needed. Let me compile the findings and write the corrected report.

**Summary of corrections for each demoted claim:**

1. `live#3aanthony.vanko` IS in MFT (parent_path of entry 108) — token needs to be quoted as bare `live#3aanthony.vanko`
2. `\\StarkResearch\Level 5–8 Classified\` is not in MFT — demote to [INFERRED]
3. Entry 2193 has `"copied":true`, `"usec_zeros":true` (not timestomped); entry 6361 has `"timestomped":true` — fix compound tokens to bare `true`
4. Same issue — `record_changed: X` and `copied: true` are compound, fix to bare values
5. Path has no trailing backslash in JSON — fix to `.\Users\PC User\AppData\Local\Microsoft\OneDrive\logs\Personal`
6. VeraCrypt install dir IS in MFT as entry `33215` at `.\\Program Files\\VeraCrypt` — add correct path
7. `01:56 UTC on June 30` is informal text — remove from backticks
8. MFT exec_id needed as multi-cite for all entry numbers/timestamps
9. `run_count: 1` compound — remove; restructure negation sentence for SMALLFTPD
10. `7ZFM.EXE`, `19841`, `2016-06-29T20:26:29Z` are in MFT — add MFT as multi-cite
11. Negation caused by "not a service account" near SID — restructure sentence
12. `A420A4D720A4B1AA` needs tsk_fs_stat exec_id multi-cite
13. Add Prefetch exec_ids; restructure negation near container-not-found claim
14. Remove erroneous `[CONFIRMED]` from footnote line

---

# DFIR Case Report — vanko-demo (Iteration 2)
## FOR500 "Abducted Zebrafish" — Insider IP Theft — Anthony Vanko
**Examiner:** SIFT-OWL v2 Orchestrator | **Date:** 2026-06-15 UTC | **Evidence:** Surface 3 physical EWF, FTK Imager (Ovie Carroll, 2016-11-04)

**Image integrity:** MD5 `4032d556cc866c23f1e797410e95603c`, SHA-1 `e0e72dfcef167dd358813726e82f6c235bc85ce7` (exec_id `019ec9d8-d2e3-7223-b211-8e71f8e949e3`)

**Partition:** C: drive at sector `1411072`, NTFS, volume serial `A420A4D720A4B1AA` (exec_ids `019ec9d8-d61a-7c01-b84b-96c8383acc6f`, `019ec9d8-e644-7e40-a146-97cb61c3bc07`)

---

## G1 — Initial Access / Involvement: Was Vanko Involved?

**[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The Windows user account on this device is named `"PC User"`. The Skype application data path in the MFT confirms this account belongs to Anthony Vanko: MFT entry `108` has parent_path containing `live#3aanthony.vanko`, specifically `.\\Users\\PC User\\AppData\\Roaming\\Skype\\live#3aanthony.vanko\\media_messaging\\emo_cache_v2`. This ties the `PC User` Windows identity to Vanko's Microsoft Live/Skype account. The active user SID is `S-1-5-21-3739107332-290452467-3466442662-1001` (confirmed via SRUDB, exec_id `019ec9de-f970-7dd1-8413-1bdeb4b613aa`).

**[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** Classified Stark Enterprises research files were present on Vanko's workstation at the time of imaging. The following files were found under `\Users\PC User\` via MFT parse:

| File | Location | MFT entry | Size (bytes) |
|---|---|---|---|
| `zebrafish.pdf` | `.\\Users\\PC User\\Documents` | `68394` | `708591` |
| `ZF DNA splice test notes.docx` | `.\\Users\\PC User\\Documents` | `13367` | `168425` |
| `Rapid cell regeneration research.docx` | `.\\Users\\PC User\\Documents` | `31868` | `480110` |
| `STARK-TS-Level7-CryoDNA Storage Inventory.docx` | `.\\Users\\PC User\\OneDrive\\Documents` | `2193` | `20124` |
| `Rapid cell regeneration research.docx` (OneDrive copy) | `.\\Users\\PC User\\OneDrive\\Documents` | `6361` | `493466` |
| `Level 7-formula 88percent ZF 0x17 close.docx` | `.\\Users\\PC User\\OneDrive\\Documents` | `124810` | `247480` |

**[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** Recent-folder LNK files corroborate that the user personally opened these files: `"zebrafish.pdf.lnk"` (entry `51827`, modified `2016-06-19T01:32:02Z`), `"ZF DNA splice test notes.docx.lnk"` (entry `8408`, modified `2016-06-29T16:20:43Z`), `"Rapid cell regeneration research.docx.lnk"` (entry `2232`, modified `2016-06-29T16:20:16Z`), `"STARK-TS-Level7-CryoDNA Storage Inventory.docx.lnk"` (entry `2235`).

**[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** A mapped drive Recent link `"STARK_ENT (D).lnk"` (entry `5030`, created `2016-05-13T19:15:07Z`) confirms Vanko had a mapped drive letter `D:` pointing to Stark Enterprises network storage.

**[INFERRED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`; reasoning: the lnk file name contains `STARK_ENT (D)` which is consistent with `\\StarkResearch\` share mapping, but the UNC path `\\StarkResearch\Level 5 Classified\` does not appear as a literal string in the MFT parse output]** The D: mapped drive is consistent with JARVIS's reported bulk transfer origin `\\StarkResearch\Level 5–8 Classified\`.

---

## G2 — Persistence / Scope: Volume of Transfer

**[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The device contains a pattern of regular STARKSURFACE IT-monitoring agent log files in `.\Windows\Temp\` and `.\Users\PC User\AppData\Local\Temp\` spanning from 2016-03-15 through 2016-11-04. This confirms the machine was authenticated to the Stark network over many months. The critical log for the incident day is `STARKSURFACE-20160630-1025.log` (entry `395`), created at `2016-06-30T14:25:38Z` — within hours of the JARVIS alert.

**[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The three classified documents stored in OneDrive share an identical `record_changed` timestamp of `2016-06-30T14:47:38Z`. The `STARK-TS-Level7-CryoDNA Storage Inventory.docx` (entry `2193`) has the MFT `copied` field set to `true` and `usec_zeros` field set to `true`, indicating it was copied from an external source rather than created locally. The `Rapid cell regeneration research.docx` (entry `6361`) in OneDrive has the `timestomped` field set to `true`, indicating timestamp manipulation consistent with anti-forensic preparation.

**[INFERRED]** The full scope of files transferred cannot be precisely quantified from disk artefacts alone — the SRUM database only retains approximately 30 days of records and at imaging time (2016-11-04) did not contain June 2016 data (exec_id `019ec9de-f970-7dd1-8413-1bdeb4b613aa`, earliest timestamp in network_usage: `2016-09-29T14:52:00Z`). However, the presence of at least three distinct classified research documents (Level 7 CryoDNA storage, ZF DNA formula/splice tests, and rapid cell regeneration) across two directory locations establishes multi-file, multi-classification-level access.

---

## G3 — Impact / Exfil Channel: What Was Done With the Data?

### Primary Exfil: Microsoft OneDrive (Cloud Sync)

**[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** All three classified documents with `record_changed` timestamp `2016-06-30T14:47:38Z` are physically stored inside `.\\Users\\PC User\\OneDrive\\Documents`. OneDrive is Microsoft's automatic cloud synchronisation service — files placed in this folder are uploaded to the user's Microsoft account. The document `STARK-TS-Level7-CryoDNA Storage Inventory.docx` (entry `2193`) has MFT `copied` field `true`, consistent with being copied directly into the OneDrive sync folder from the mapped Stark network drive.

**[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** OneDrive client activity logs exist under `.\\Users\\PC User\\AppData\\Local\\Microsoft\\OneDrive\\logs\\Personal`, with the trace archive entry `47` (`TraceArchive.6390.0509-79.etl`, modified `2016-10-30T23:12:56Z`), confirming the OneDrive client was active and syncing during the incident period.

### Secondary Exfil Mechanism: VeraCrypt Encrypted Container

**[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** `VeraCrypt Setup 1.17.exe` was downloaded from the internet to `.\\Users\\PC User\\Downloads` on `2016-06-29T15:51:16Z` (entry `32010`, Zone.Identifier ADS confirms web download). VeraCrypt was installed to `.\\Program Files\\VeraCrypt` (directory entry `33215`, created `2016-06-29T16:03:13Z`) — exactly one day before the JARVIS alert.

**[CONFIRMED — exec_id `019ec9e1-22d0-7bb3-8660-e76f6210c4b7`]** `VERACRYPT FORMAT.EXE` — the volume creation tool — ran `6` times. Run history: `2016-06-29T16:12:23Z`, `2016-06-29T16:32:16Z`, `2016-06-29T16:32:41Z`, `2016-06-29T16:34:32Z`, `2016-06-29T20:32:30Z`, last run `2016-06-30T01:14:42Z`. The six runs indicate multiple volume creation attempts (testing passwords/sizes before the final container).

**[CONFIRMED — exec_id `019ec9e1-1e8b-71d2-862b-43bf884db914`]** `VERACRYPT.EXE` — the main VeraCrypt executable for mounting containers — also ran `6` times: `2016-06-29T16:12:13Z`, `2016-06-29T20:25:57Z`, `2016-06-29T20:32:27Z`, `2016-06-30T01:12:53Z`, `2016-06-30T01:40:51Z`, last run `2016-06-30T01:56:46Z`.

**[CONFIRMED — exec_id `019ec9e1-1e8b-71d2-862b-43bf884db914`, `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The VeraCrypt Prefetch references `\USERS\PC USER\APPDATA\ROAMING\VERACRYPT\HISTORY.XML` and `\USERS\PC USER\APPDATA\ROAMING\VERACRYPT\CONFIGURATION.XML`. These files are present on disk under `.\\Users\\PC User\\AppData\\Roaming\\VeraCrypt` (directory entry `33344`, modified `2016-06-29T20:11:03Z`). The History.xml is MFT entry `4397` (modified `2016-06-29T20:32:56Z`) and Configuration.xml is MFT entry `29963` (modified `2016-06-29T20:37:00Z`).

**[HYPOTHESIS]** The VeraCrypt encrypted container file itself was likely removed or moved to removable/external media before imaging in November 2016. No large unusually-named file without extension was identified in standard user directories. The container's final destination — USB, secondary cloud service, or physical handoff — cannot be confirmed from disk artefacts alone.

### Tertiary: Small FTP Server

**[CONFIRMED — exec_id `019ec9e1-27ec-7e61-999c-c7b2630cb6bc`]** `SMALLFTPD.EXE` — a small Windows FTP server — last ran on `2016-06-18T22:02:05Z`, launched from the `defaultprinter` account's home directory at `\USERS\DEFAULTPRINTER\SMALLFTPD.EXE`. This predates the main exfil activity by 12 days and may represent reconnaissance or an earlier, smaller data staging operation.

### Additional: 7-Zip Archive Tool

**[CONFIRMED — exec_id `019ec9e1-2a33-7200-bd91-7b41cecaf0ea`, `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** `7Z1602-X64.EXE` (7-Zip v16.02 installer) ran once at `2016-06-29T16:01:38Z` from `\USERS\PC USER\DOWNLOADS\7Z1602-X64.EXE` — immediately before VeraCrypt installation. The 7-Zip File Manager Prefetch `7ZFM.EXE-44040917.pf` (MFT entry `19841`) has a created timestamp of `2016-06-29T20:26:29Z`, confirming `7ZFM.EXE` was first executed concurrently with VeraCrypt operations, suggesting Vanko archived research documents before encrypting them.

### Exfil Channels NOT Evidenced

**[GAP]** No Prefetch entries were found for `ROBOCOPY.EXE`, `XCOPY.EXE`, `WINSCP.EXE`, `FILEZILLA.EXE`, `PUTTY.EXE`, or `WGET.EXE`. Dropbox Update was found in Prefetch (`DROPBOXUPDATE.EXE-E72FEFE1.pf`, inode `3100`), but Dropbox Update running does not confirm data exfiltration via Dropbox — it may simply be background update checks.

---

## G4 — Attribution: Was It Vanko Personally?

**[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The Skype data path for MFT entry `108` has parent_path `live#3aanthony.vanko` under `.\\Users\\PC User\\AppData\\Roaming\\Skype\\`, tying the `PC User` Windows account to Anthony Vanko's Microsoft Live identity.

**[CONFIRMED — exec_id `019ec9de-f970-7dd1-8413-1bdeb4b613aa`]** The SRUDB.dat push_notifications provider associates SID `S-1-5-21-3739107332-290452467-3466442662-1001` with personal consumer application packages (Bing Finance, Bing News, Flipboard), confirming this SID belongs to an active personal user account engaged in normal consumer activities.

**[CONFIRMED — exec_id `019ec9e1-1e8b-71d2-862b-43bf884db914`, `019ec9e1-22d0-7bb3-8660-e76f6210c4b7`]** VeraCrypt configuration data (`HISTORY.XML`, `CONFIGURATION.XML`) is stored under `\Users\PC User\AppData\Roaming\VeraCrypt\`, confirming Vanko's interactive session installed and operated VeraCrypt. Both Prefetch records report `volume_serial` `20A4B1AA` (the short form of the C: volume serial `A420A4D720A4B1AA`, confirmed by tsk_fs_stat exec_id `019ec9d8-e644-7e40-a146-97cb61c3bc07`), grounding all Prefetch activity on the imaged device.

**[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The STARKSURFACE IT-monitoring logs in `.\Windows\Temp\` and `.\Users\PC User\AppData\Local\Temp\` show the machine regularly connecting to the Stark network during business hours across months. The log `STARKSURFACE-20160630-1025.log` (entry `395`, created `2016-06-30T14:25:38Z`) captures the June 30 session on the incident day.

**[INFERRED]** No evidence of remote desktop, remote logon type 10, or a second user account conducting these actions was found. The `defaultprinter` secondary account (which ran SMALLFTPD.EXE) appears to be a service or secondary profile; all classified document access and VeraCrypt activity is scoped exclusively to the `PC User` (Vanko) profile directory.

### Anti-Forensic Activity

**[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`, `019ec9e1-1e8b-71d2-862b-43bf884db914`, `019ec9e1-22d0-7bb3-8660-e76f6210c4b7`]** The VeraCrypt encrypted container file is absent from all user-visible directories at imaging time. VeraCrypt Format.exe last ran at `2016-06-30T01:14:42Z` and VeraCrypt.exe last ran at `2016-06-30T01:56:46Z` (Prefetch exec_ids cited). The device was not imaged until `2016-11-04T17:47:41Z`, leaving a 4+ month window during which the container was deleted, transferred to USB, or uploaded via a cloud service. Additionally, the `Rapid cell regeneration research.docx` in OneDrive (entry `6361`) has the MFT `timestomped` field set to `true`, indicating timestamp manipulation on at least one classified document.

---

## Summary Timeline

| Time (UTC) | Event |
|---|---|
| `2016-03-06T02:45:20Z` | `zebrafish.pdf` created on workstation |
| `2016-03-15T00:14:54Z` | `Rapid cell regeneration research.docx` first created in OneDrive |
| `2016-04-30T17:09:39Z` | `STARK-TS-Level7-CryoDNA Storage Inventory.docx` first created on workstation |
| `2016-06-15T10:48:57Z` | `ZF DNA splice test notes.docx` created in Documents |
| `2016-06-29T15:51:16Z` | `VeraCrypt Setup 1.17.exe` downloaded from internet |
| `2016-06-29T16:01:38Z` | 7-Zip installer executed from Downloads |
| `2016-06-29T16:03:13Z` | VeraCrypt installed to `.\Program Files\VeraCrypt` |
| `2016-06-29T16:12:13Z` | VeraCrypt.exe and Format.exe first executed |
| `2016-06-29T20:26:29Z` | 7ZFM.EXE first execution (archiving research files) |
| `2016-06-29T20:32:30Z` | VeraCrypt Format.exe run again (container creation) |
| `2016-06-30T01:14:42Z` | VERACRYPT FORMAT.EXE last run (final container creation) |
| `2016-06-30T01:40:51Z`–`01:56:46Z` | VERACRYPT.EXE last two runs (mounting, copying data to container) |
| `2016-06-30T14:25:38Z` | STARKSURFACE log records workstation active on Stark network |
| `2016-06-30T14:47:38Z` | Three classified docs record_changed in OneDrive (sync upload) |
| `2016-11-04T17:47:41Z` | Device imaged by Ovie Carroll |

All `[CONFIRMED]` claims cite the exec_id of the tool whose parsed JSON contains the quoted tokens. Claims tagged `[INFERRED]` are logical conclusions from confirmed artefacts. `[HYPOTHESIS]` indicates analytic inference where direct evidence is absent. `[GAP]` denotes collection limitations.

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

### Demotion list — 10 claims

**[1] not_confirmed** — cited tool(s): — — exec_ids: (none)
- validator note: claim is tagged CONFIRMED but cites no exec_id
> 3. Entry 2193 has `"copied":true`, `"usec_zeros":true` (not timestomped); entry 6361 has `"timestomped":true` — fix compound tokens to bare `true` 4. Same issue — `record_changed: X` and `copied: true` are compound, fix to bare values 5. Path has no trailing backslash in JSON — f…


**[2] partial** — cited tool(s): ezt_mft_parse — exec_ids: 019ec9d9-1d2b-7532-bd75-173ab081dfe2
- missing tokens (claim says X but X not in cited tool's data): `. This ties the `
- already matched: `"PC User"`, `108`, `live#3aanthony.vanko`, `S-1-5-21-3739107332-290452467-3466442662-1001`
> **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The Windows user account on this device is named `"PC User"`. The Skype application data path in the MFT confirms this account belongs to Anthony Vanko: MFT entry `108` has parent_path containing `live#3aanthony.van…


**[3] partial** — cited tool(s): ezt_mft_parse — exec_ids: 019ec9d9-1d2b-7532-bd75-173ab081dfe2
- missing tokens (claim says X but X not in cited tool's data): `.\\Users\\PC User\\OneDrive\\Documents`
- already matched: `2016-06-30T14:47:38Z`, `Inventory.docx`, `copied`, `STARK-TS-Level7-CryoDNA Storage Inventory.docx`, `2193`, `true` (+1 more)
> **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** All three classified documents with `record_changed` timestamp `2016-06-30T14:47:38Z` are physically stored inside `.\\Users\\PC User\\OneDrive\\Documents`. OneDrive is Microsoft's automatic cloud synchronisation se…


**[4] partial** — cited tool(s): ezt_mft_parse — exec_ids: 019ec9d9-1d2b-7532-bd75-173ab081dfe2
- missing tokens (claim says X but X not in cited tool's data): `.\\Users\\PC User\\AppData\\Local\\Microsoft\\OneDrive\\logs\\Personal`
- already matched: `2016-10-30T23:12:56Z`, `TraceArchive.6390.0509-79.etl`, `47`
> **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** OneDrive client activity logs exist under `.\\Users\\PC User\\AppData\\Local\\Microsoft\\OneDrive\\logs\\Personal`, with the trace archive entry `47` (`TraceArchive.6390.0509-79.etl`, modified `2016-10-30T23:12:56Z`…


**[5] partial** — cited tool(s): ezt_mft_parse — exec_ids: 019ec9d9-1d2b-7532-bd75-173ab081dfe2
- missing tokens (claim says X but X not in cited tool's data): `.\\Users\\PC User\\Downloads`, `.\\Program Files\\VeraCrypt`
- already matched: `2016-06-29T16:03:13Z`, `2016-06-29T15:51:16Z`, `1.17.exe`, `VeraCrypt Setup 1.17.exe`, `33215`, `32010`
> **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** `VeraCrypt Setup 1.17.exe` was downloaded from the internet to `.\\Users\\PC User\\Downloads` on `2016-06-29T15:51:16Z` (entry `32010`, Zone.Identifier ADS confirms web download). VeraCrypt was installed to `.\\Prog…


**[6] partial** — cited tool(s): ezt_prefetch_parse, ezt_mft_parse — exec_ids: 019ec9e1-1e8b-71d2-862b-43bf884db914, 019ec9d9-1d2b-7532-bd75-173ab081dfe2
- missing tokens (claim says X but X not in cited tool's data): `.\\Users\\PC User\\AppData\\Roaming\\VeraCrypt`
- already matched: `2016-06-29T20:32:56Z`, `2016-06-29T20:37:00Z`, `2016-06-29T20:11:03Z`, `\USERS\PC USER\APPDATA\ROAMING\VERACRYPT\CONFIGURATION.XML`, `29963`, `4397` (+2 more)
> **[CONFIRMED — exec_id `019ec9e1-1e8b-71d2-862b-43bf884db914`, `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The VeraCrypt Prefetch references `\USERS\PC USER\APPDATA\ROAMING\VERACRYPT\HISTORY.XML` and `\USERS\PC USER\APPDATA\ROAMING\VERACRYPT\CONFIGURATION.XML`. These files are pres…


**[7] partial** — cited tool(s): ezt_mft_parse — exec_ids: 019ec9d9-1d2b-7532-bd75-173ab081dfe2
- missing tokens (claim says X but X not in cited tool's data): `.\\Users\\PC User\\AppData\\Roaming\\Skype\\`
- already matched: `108`, `live#3aanthony.vanko`, `PC User`
> **[CONFIRMED — exec_id `019ec9d9-1d2b-7532-bd75-173ab081dfe2`]** The Skype data path for MFT entry `108` has parent_path `live#3aanthony.vanko` under `.\\Users\\PC User\\AppData\\Roaming\\Skype\\`, tying the `PC User` Windows account to Anthony Vanko's Microsoft Live identity.


**[8] partial** — cited tool(s): ezt_srum_parse — exec_ids: 019ec9de-f970-7dd1-8413-1bdeb4b613aa
- missing tokens (claim says X but X not in cited tool's data): `SRUDB.dat`
- already matched: `S-1-5-21-3739107332-290452467-3466442662-1001`
> **[CONFIRMED — exec_id `019ec9de-f970-7dd1-8413-1bdeb4b613aa`]** The SRUDB.dat push_notifications provider associates SID `S-1-5-21-3739107332-290452467-3466442662-1001` with personal consumer application packages (Bing Finance, Bing News, Flipboard), confirming this SID belongs …


**[9] partial** — cited tool(s): ezt_prefetch_parse, ezt_prefetch_parse — exec_ids: 019ec9e1-1e8b-71d2-862b-43bf884db914, 019ec9e1-22d0-7bb3-8660-e76f6210c4b7
- missing tokens (claim says X but X not in cited tool's data): `A420A4D720A4B1AA`
- already matched: `\Users\PC`, `CONFIGURATION.XML`, `volume_serial`, `HISTORY.XML`, `20A4B1AA`, `\Users\PC User\AppData\Roaming\VeraCrypt\`
> **[CONFIRMED — exec_id `019ec9e1-1e8b-71d2-862b-43bf884db914`, `019ec9e1-22d0-7bb3-8660-e76f6210c4b7`]** VeraCrypt configuration data (`HISTORY.XML`, `CONFIGURATION.XML`) is stored under `\Users\PC User\AppData\Roaming\VeraCrypt\`, confirming Vanko's interactive session installed…


**[10] not_confirmed** — cited tool(s): — — exec_ids: (none)
- validator note: claim is tagged CONFIRMED but cites no exec_id
> All `[CONFIRMED]



---

When you produce iteration 3's report, end with the line `SIFT-OWL RUN COMPLETE`.
