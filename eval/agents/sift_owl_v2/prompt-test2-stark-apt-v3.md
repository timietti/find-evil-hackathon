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

**Token-quoting style (W3-60):** the validator extracts backticked
tokens individually and substring-matches them against the cited
tool's parsed JSON. Quote **bare values**, NOT `field_name "value"`
compounds. The JSON haystack stores each field as `"FileName":
"value"` (with a colon); a compound like `file_name "value"` is a
literal string that does not appear there.

| Token type | Good | Bad |
|---|---|---|
| numbers (PID, inode, port, byte count, MFT entry, sector) | `` `8260` `` | `` `pid 8260` `` |
| strings (filenames, user names, hostnames) | `` `"p.exe"` ``, `` `usboesrv.exe` `` | `` `image "p.exe"` ``, `` `name="usboesrv.exe"` `` |
| paths | `` `\Users\vibranium\` `` | `` `parent_path ".\Users\vibranium\"` `` |
| booleans / enums | `` `true` ``, `` `ESTABLISHED` `` | `` `is_directory true` ``, `` `state "ESTABLISHED"` `` |
| timestamps | `` `2012-04-06T20:14:10Z` `` | `` `created_at "2012-04-06T20:14:10Z"` `` |
| hashes | `` `7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c` `` | `` `sha256 "7fa4f6cc..."` `` |

If you want to make the field name visible in the prose, write it
as natural English outside the backticks ("the image field is
`"p.exe"`") rather than fusing it into the token.

When you are done, print `SIFT-OWL RUN COMPLETE` to stdout.
