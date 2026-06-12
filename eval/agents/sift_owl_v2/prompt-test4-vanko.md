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
