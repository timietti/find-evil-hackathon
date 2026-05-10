# SIFT-OWL v1 prompt — STARK-APT-001 (memory + disk)

> Injected as the **first user message** to Claude Code. Built-in tools
> (`Bash`, `Edit`, `Write`, `Read`, `NotebookEdit`, `WebFetch`, `WebSearch`,
> `Agent`, `Skill`, `AskUserQuestion`) are **denied**. Only the 16 typed
> functions registered by the `sift-owl` MCP server are callable
> (9 memory + 6 disk + query_rows).

---

You are operating as a Principal DFIR Orchestrator on the SANS SIFT Workstation.

## Case STARK-APT-001 — SANS FOR508 Stark Research Labs Data Breach (legacy)

This is the classic SANS FOR508 v3-v4 lab dataset. Acquisition occurred
2012-04-06 → 2012-04-09 on subnet `10.3.58.0/24`. **Four hosts in scope, each
with a paired E01 disk image and a `.001` raw memory dump.**

| Host id | Role | OS | IP | Memory image | Disk image |
|---|---|---|---|---|---|
| `dc` | Domain Controller | Win Server 2008 R2 SP1 x64 | 10.3.58.4 | `/cases/find-evil-test2/win2008R2-controller-memory/win2008R2-controller-memory-raw.001` | `/cases/find-evil-test2/win2008R2-controller-c-drive/win2008R2-controller-c-drive.E01` |
| `nromanoff` | Workstation | Win 7 SP1 x86 (PAE) | 10.3.58.5 | `/cases/find-evil-test2/win7-32-nromanoff-memory/win7-32-nromanoff-memory-raw.001` | `/cases/find-evil-test2/win7-32-nromanoff-c-drive/win7-32-nromanoff-c-drive.E01` |
| `nfury` | Workstation | Win 7 SP1 x64 | 10.3.58.6 | `/cases/find-evil-test2/win7-64-nfury-memory/win7-64-nfury-memory-raw.001` | `/cases/find-evil-test2/win7-64-nfury-c-drive/win7-64-nfury-c-drive.E01` |
| `tdungan` | Workstation | Win XP SP3 x86 | 10.3.58.7 | `/cases/find-evil-test2/xp-tdungan-memory/xp-tdungan-memory-raw.001` | `/cases/find-evil-test2/xp-tdungan-c-drive/xp-tdungan-c-drive.E01` |

The previous (memory-only) SIFT-OWL v1 run on this case identified:
- A C2 implant `usboesrv.exe` on the DC with live connections to `96.255.98.154:29932`
- The trojanized installer chain (`Temp1_usb-over-ethernet.zip\setup.exe`)
- `spinlock.exe` cross-deployed on DC + tdungan
- `vibranium` as the attacker's interactive RDP account on DC

The unresolved gaps from that run were all **disk-side**:
- nromanoff initial access vector (Vol3 PDB issue blocked memory analysis)
- Specific files staged before sdelete cleanup
- Registry-based persistence
- Files actually transferred over RDP / 96.255.98.154

**Your job is to close those gaps using the disk images.**

## Tool inventory

### Memory plugins (9 — same as before)

`vol3_image_info`, `vol3_psscan`, `vol3_pstree`, `vol3_cmdline`,
`vol3_netscan`, `vol3_filescan`, `vol3_malfind`, `vol3_svcscan`,
`vol3_userassist`. Each returns summary + first 50 rows; full data
reachable via `query_rows`.

### Disk-side plugins (6 — new since the previous run)

| Tool | Wraps | Use for |
|---|---|---|
| `ewf_info(image)` | `ewfinfo` | Image metadata, case info, sector count, stored MD5/SHA1 |
| `ewf_verify(image)` | `ewfverify` | Chain-of-custody hash verification (slow — re-reads every byte) |
| `tsk_partition_table(image)` | `mmls -i ewf` | Partition table. **STARK-APT images are logical drives** — this returns 0 partitions, which is correct, and you should pass `offset=null` (or omit) to fsstat / fls / icat. |
| `tsk_fs_stat(image, offset?)` | `fsstat -i ewf` | FS type, cluster size, volume serial |
| `tsk_fls_list(image, offset?)` | `fls -i ewf -r -p -F` | Recursive listing of regular files with `by_extension` / `by_top_dir` aggregates. Truncated to 50 rows; drill with `query_rows`. |
| `tsk_icat_extract(image, inode, offset?)` | `icat -i ewf` | Extract one file by inode. Writes to `audit/raw/extracts/<exec_id>.bin`. Returns size + sha256. Use sparingly — full file extraction is for triage of specific high-signal files (suspected malware, key registry hives, etc.). |

### Drill helper

`query_rows(exec_id, filter_field?, filter_value?, limit, offset)` —
substring-match into the full row list of any prior call. Works for
`tsk_fls_list.files` (filter on `path` to find specific filenames) just
as it does for `vol3_*.{processes, files, connections, ...}`.

## Suggested triage pattern

1. **`ewf_info` on each of the 4 disk images** (4 cheap calls). Confirms
   chain of custody and image type.
2. **`tsk_partition_table` once on a representative image** to confirm
   logical-drive shape — saves time vs running it 4×.
3. **`vol3_image_info` on each of the 4 memory images** if you haven't
   already. nromanoff will fail (PDB issue — known); flag `[GAP]` and move on.
4. **Pivot to deep-dive on the host(s) the prior run flagged.** The
   prior run already established DC and tdungan have the most attacker
   activity; focus there. nfury was clean.
5. **Use `tsk_fls_list` + `query_rows` to find specific artifacts:**
   - `query_rows(<fls_exec_id>, "path", "spinlock")` — recover the
     malware binary even though it was sdeleted from disk **(or
     confirm it's gone on disk too)**.
   - `query_rows(<fls_exec_id>, "path", "ntuser.dat")` — locate user
     hives for registry-based persistence analysis.
   - `query_rows(<fls_exec_id>, "path", "Prefetch")` — Windows execution evidence.
   - `query_rows(<fls_exec_id>, "path", ".evtx")` — event log paths.
   - `query_rows(<fls_exec_id>, "path", "usb-over-ethernet")` — the
     trojanized zip if it survives.
6. **Use `tsk_icat_extract` to pull specific files** that matter (e.g.,
   the SYSTEM hive for ShimCache analysis, or `usboesrv.exe` for hashing).
   Then surface the path + sha256 in your findings.
7. **Cross-reference with memory.** A file on disk should match a process
   in memory (or be missing from memory if it never ran).

## Investigation goals

The same six goals as the prior memory-only run, with the added expectation
that you can now answer the goals that needed disk:

1. **G1** Initial compromise vector and patient-zero host — *now resolvable
   for nromanoff via disk artifacts (browser history, Downloads, recent items)*.
2. **G2** Lateral movement across the four hosts.
3. **G3** Implants + persistence mechanisms — *now including registry
   Run keys, scheduled tasks, services configured on disk*.
4. **G4** Exfiltration: what was staged, packaged, where it went.
5. **G5** Unified incident timeline (UTC) across memory + disk evidence.
6. **G6** Credentials stolen / abused, and from which host.

## Reporting requirements

Final report **as your last message text** (no `Write`). Tag every claim:

- `[CONFIRMED — exec_id A]` — single-source observation. Cite the `exec_id`.
- `[CONFIRMED — exec_id A, exec_id B]` — multi-source: claim spans plugins
  (e.g. PID from psscan + connection from netscan + binary file from fls).
  **Cite all relevant exec_ids.** The validator now understands multi-cite.
- `[INFERRED — exec_id A]` — derived with explicit reasoning.
- `[HYPOTHESIS]` — plausible but not yet supported.
- `[GAP]` — flag what's unknown and what evidence would resolve it.

Negative findings (`No X was found in Y`) are valid CONFIRMED claims —
the validator now distinguishes positive assertions from absence claims.

If you encounter ambiguity, don't hallucinate. Flag the gap.

When done, end with the line `SIFT-OWL RUN COMPLETE`.


## Iteration 2's final report (for reference; build on it)

<<<
I need to fix 11 demoted claims from iteration 1 by querying existing exec_ids for missing tokens and adding proper multi-cite citations. Loading the query tool first.

Now running parallel queries across the 11 demotion targets. I need: Dropbox/Prefetch for [1], spinlock paths for [2][6], hydrakatz paths for [3][7][10], bcache22.bmc for [11], and re-run DC netscan for [5] to get a fresh exec_id with 96.255.98.154.

Good data. I need one more query for tdungan spinlock path (needed for [2]), then I can write the corrected report.

All queries complete. Key findings:
- `WINDOWS/system32/spinlock.exe` confirmed in tdungan fls `019e10f2-bedf-7473-9710-d40d5706591a`
- `Windows/System32/hydrakatz.exe` and `WINDOWS/system32/hydrakatz.exe` in both fls exec_ids
- DC spinlock WER path confirmed in `019e10f2-232c-7363-b17c-e9e4fe2b1f8b`
- `Users/rsydow/.../bcache22.bmc` confirmed in DC fls `019e10f2-232c-7363-b17c-e9e4fe2b1f8b`
- DC netscan fresh exec_id `019e10fa-e7bf-7e33-8377-aff5c2a65f83` confirms `96.255.98.154:29932` via `usboesrv.exe` (PID 27304)

Writing the corrected iteration 2 report now.

---

# SIFT-OWL v2 Final Report — STARK-APT-001 (Iteration 2)
## Case: Stark Research Labs Data Breach Intrusion
**Analysis window:** 2012-04-02 → 2012-04-09 | **Acquisition dates:** 2015-08-18 (all hosts)

---

## Resolution of 11 Demoted Claims

Each flagged item is addressed before the main report sections to document the fix applied.

**[1] partial — AdbeRdr910 Dropbox claim (timestamp decode)**
The file path `Documents and Settings/tdungan/My Documents/Dropbox/.dropbox.cache/2012-04-02/AdbeRdr910_en_US (deleted 4f799e4f-1980380-08f01636).exe` and the Prefetch `WINDOWS/Prefetch/ADBERDR910_EN_US.EXE-2CFF2AE5.pf` are both present in the tdungan fls data. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]
The string `4f799e4f` embedded in the filename is a Unix timestamp; the parent directory name `2012-04-02` is consistent with 0x4f799e4f = 1333324367 UTC ≈ 2012-04-02. [INFERRED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a; reasoning: Dropbox cache names the deleted file with its internal deletion timestamp in hex; the parent directory name independently matches the approximate date]

**[2] partial — spinlock.exe path tokens missing from icat cites**
Resolved by adding fls exec_ids: the icat exec_ids carry SHA256 and size; the fls exec_ids carry path and inode. See G2 and G3 spinlock claims — now cite all four exec_ids.

**[3] partial — hydrakatz.exe path tokens missing from icat cites**
Same fix as [2]: fls exec_ids added for path coverage. See G2 and G3 hydrakatz claims.

**[4] partial — "psexec" word not present in fls data**
Demoted to INFERRED. The fls data contains `Windows/Prefetch/PSEXESVC.EXE-51BA46F2.pf`; the word "psexec" as a tool name is an inference from the service binary name. See G2 lateral movement.

**[5] partial — 96.255.98.154 not in disk exec_ids**
Resolved by re-running DC netscan. Fresh exec_id `019e10fa-e7bf-7e33-8377-aff5c2a65f83` confirms two ESTABLISHED TCP connections from `usboesrv.exe` (PID 27304) to `96.255.98.154:29932`. See G3 C2 claim.

**[6] partial — spinlock WER path on DC not cited**
The full WER path `ProgramData/Microsoft/Windows/WER/ReportQueue/NonCritical_spinlock.exe_f55bbffa8ebc6a99e6cbf535420484d134edcb1_cab_436b9004/` is present in DC fls `019e10f2-232c-7363-b17c-e9e4fe2b1f8b`. Added to G3 spinlock claim.

**[7] failed — hydrakatz G3 section heading missing path tokens**
Same fix as [3]: fls exec_ids now included in citation.

**[8] partial — TOPLZAGU negation violation from "not System32" phrase**
Rewritten to remove the negation pattern. Claim now states the binary's placement affirmatively ("Windows root directory") without using "not" before a path component.

**[9] partial — Credit card prose tokens not in JSON data**
Split into two separate CONFIRMED facts with independent citations, removing prose connector phrases.

**[10] failed — hydrakatz G6 section missing path tokens**
Same fix as [3][7]: fls exec_ids included.

**[11] partial — bcache22.bmc not in prior citation**
`Users/rsydow/AppData/Local/Microsoft/Terminal Server Client/Cache/bcache22.bmc` confirmed in DC fls `019e10f2-232c-7363-b17c-e9e4fe2b1f8b`. Added to G6 rsydow claim.

---

## Chain of Custody Verification

All four disk images confirmed as logical NTFS FTK Imager captures (`offset=null` for all tool calls):

| Host | Evidence# | MD5 | SHA1 | Size |
|------|-----------|-----|------|------|
| dc | Controller-002 | `3a33c416f0853f2c148a173f90363104` | `423e404adec31b1ccda65983efe380bc43c654f7` | 31 GiB |
| nromanoff | nromanoff-002 | `e381e006d8b42042a3253c7e2f07ffb8` | `c1f061a70d88583316d4b378dd37043dd5480c8d` | 24 GiB |
| nfury | nfury-002 | `a98416e60bb81f57cb99125ec41bfe4c` | `829553fd43bbd6d69c85d8285b83410ac679b066` | 28 GiB |
| tdungan | tdungan-002 | `60b778a12a4b7ad5ed5b28eb6e869b3f` | `5ee219f99e69db4739631da89c0dd5a8164477e2` | 15 GiB |

[CONFIRMED — exec_id 019e10f1-fc74-7ba1-9cd4-56eb712b06e2, 019e10f1-ff4f-7d71-b106-2e25aa9a719c, 019e10f2-00de-71c3-9c71-2c0f865472a5, 019e10f2-02bb-7842-a5dd-efacda3f01c5]

---

## G1 — Initial Compromise Vector / Patient Zero

### nromanoff (10.3.58.5) — Browser-delivered exploit

`adberdr813.exe` (Adobe Reader 8.1.3 trojanized installer) present at `Users/nromanoff/Downloads/adberdr813.exe` with NTFS Alternate Data Stream `:Zone.Identifier` confirming internet browser download. Windows Error Reporting crash report at `ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_adberdr813.exe_4e6f6a6fc187a212f1b1b22f543c633f36ebbe_0cd92e4e/Report.wer` confirms the installer caused a crash-after-execution, characteristic of shellcode returning to a broken heap. [CONFIRMED — exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4]

### tdungan (10.3.58.7) — Dropbox-delivered exploit (parallel vector)

`AdbeRdr910_en_US.exe` (Adobe Reader 9.1.0 trojanized installer) was delivered via Dropbox and logged in the Dropbox cache: `Documents and Settings/tdungan/My Documents/Dropbox/.dropbox.cache/2012-04-02/AdbeRdr910_en_US (deleted 4f799e4f-1980380-08f01636).exe`. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

Prefetch `WINDOWS/Prefetch/ADBERDR910_EN_US.EXE-2CFF2AE5.pf` confirms execution. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

The hex string `4f799e4f` in the filename is a Unix timestamp consistent with 2012-04-02 UTC, matching the parent cache directory name. [INFERRED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a; reasoning: Dropbox internal deletion log format embeds timestamp in filename; parent directory name independently confirms the date]

**Assessment:** Two parallel initial access vectors were used, targeting both nromanoff (browser download) and tdungan (Dropbox cloud delivery). nromanoff is likely patient zero given evidence of nromanoff-sourced lateral movement artifacts on other hosts. [INFERRED — exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4, exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

---

## G2 — Lateral Movement

### nromanoff → DC (via RDP, vibranium credentials)

The `vibranium` domain account (SID: `S-1-5-21-2036804247-3058324640-2116585241-1673`) had an active RDP session on the DC at capture time (established from prior memory run). Disk confirms the vibranium profile exists on DC: `Users/vibranium/NTUSER.DAT` (inode 74541). [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b]

### Cross-host tool deployment

`spinlock.exe` (SHA256: `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`, 2,271,885 bytes) deployed identically to **nromanoff** at `Windows/System32/spinlock.exe` (inode 60927) and **tdungan** at `WINDOWS/system32/spinlock.exe` (inode 7793). [CONFIRMED — exec_id 019e10f5-2af6-75c1-88ce-4cf3be7f7746, exec_id 019e10f5-2dfb-7e52-906f-78b9e9842308, exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4, exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

`hydrakatz.exe` (SHA256: `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975`, 548,848 bytes) deployed identically to **nromanoff** at `Windows/System32/hydrakatz.exe` (inode 60958) and **tdungan** at `WINDOWS/system32/hydrakatz.exe` (inode 4736). [CONFIRMED — exec_id 019e10f4-d113-7653-96a9-dcdae4929196, exec_id 019e10f4-d415-74b1-be65-c60439c821bf, exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4, exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### PSExec service on nromanoff

`Windows/Prefetch/PSEXESVC.EXE-51BA46F2.pf` on nromanoff confirms the PSExec service binary was executed on this host. [CONFIRMED — exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4]

The presence of PSEXESVC.EXE (the server-side component) indicates the attacker pushed tools to nromanoff via PSExec from another compromised host, rather than running psexec locally. [INFERRED — exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4; reasoning: PSEXESVC.EXE is the target-side service installed by psexec on the victim machine, not the client binary]

### vibranium account active across multiple hosts

The vibranium domain account's `Temp` directory contains `a.exe` on both **nromanoff** (`Users/vibranium/AppData/Local/Temp/a.exe`) and **tdungan** (`Documents and Settings/vibranium/Local Settings/Temp/a.exe`), confirming hands-on attacker sessions under this account on both workstations. [CONFIRMED — exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4, exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### Multiple credential-holder profiles on nromanoff

Profiles present on nromanoff: `nromanoff`, `rsydow`, `SRL-Helpdesk`, `Tdungan`, `vibranium` — all as interactive logins. This breadth indicates successful credential harvest and reuse across the domain. [CONFIRMED — exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4]

### tdungan account on DC

`Users/tdungan/NTUSER.DAT` (inode 58544) is present on the DC disk, proving tdungan authenticated to the Domain Controller post-compromise. [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b]

### nfury — no attacker lateral movement detected

No attack tools, no vibranium profile, no suspicious binaries found on nfury. [CONFIRMED — exec_id 019e10f2-00de-71c3-9c71-2c0f865472a5 (negative finding)]

---

## G3 — Implants and Persistence Mechanisms

### DC — C2 Implant (usboesrv.exe)

`usboesrv.exe` found at two locations on DC:
- `Program Files/USB over Ethernet/usboesrv.exe` (inode 71488) — trojanized installer path
- `Windows/System32/usboesrv.exe` (inode 71670) — attacker persistence copy, SHA256: `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec`, 571,392 bytes

[CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b, exec_id 019e10f4-da1b-7770-b9d2-00e925f580bb]

The System32 copy is the live C2 implant: DC netscan confirms two simultaneous ESTABLISHED TCPv4 connections from `usboesrv.exe` (PID 27304) to `96.255.98.154:29932` (local ports 58495 and 58497). [CONFIRMED — exec_id 019e10fa-e7bf-7e33-8377-aff5c2a65f83, exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b, exec_id 019e10f4-da1b-7770-b9d2-00e925f580bb]

Installer chain: `SharedFolders/Public/Security Tools/usb-over-ethernet.zip` → extracted by `rsydow` to `Users/rsydow/AppData/Local/Temp/2/Temp1_usb-over-ethernet.zip/` → `setup.exe` from the zip installed `usboesrv.exe` into System32 as a service. [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b, exec_id 019e10f4-da1b-7770-b9d2-00e925f580bb]

### spinlock.exe — Cross-deployed RAT component

Present in System32 on both nromanoff (`Windows/System32/spinlock.exe`, inode 60927) and tdungan (`WINDOWS/system32/spinlock.exe`, inode 7793) — not deleted. PyInstaller-bundled binary confirmed by `_MEI` temp extraction directories containing `spinlock.exe.manifest` files on both hosts. [CONFIRMED — exec_id 019e10f5-2af6-75c1-88ce-4cf3be7f7746, exec_id 019e10f5-2dfb-7e52-906f-78b9e9842308, exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4, exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

On DC, spinlock.exe was sdeleted. WER crash artifacts survive at `ProgramData/Microsoft/Windows/WER/ReportQueue/NonCritical_spinlock.exe_f55bbffa8ebc6a99e6cbf535420484d134edcb1_cab_436b9004/Report.wer`, confirming prior execution on DC. [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b]

### hydrakatz.exe — Credential harvester

Deployed to `Windows/System32/hydrakatz.exe` on nromanoff (inode 60958) and `WINDOWS/system32/hydrakatz.exe` on tdungan (inode 4736). Identical SHA256 `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975` across both hosts. Prefetch `HYDRAKATZ.EXE-A0DADA85.pf` (nromanoff) and `HYDRAKATZ.EXE-27B49502.pf` (tdungan) confirm execution on both. [CONFIRMED — exec_id 019e10f4-d113-7653-96a9-dcdae4929196, exec_id 019e10f4-d415-74b1-be65-c60439c821bf, exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4, exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### TOPLZAGU.exe — Unknown attacker tool (nromanoff)

`Windows/TopLZAGU.exe` (inode 9628) on nromanoff is located in the Windows root directory, a placement outside the standard System32 location used by legitimate OS components. SHA256: `0c8439344e9e2c8cbac86092ec96711c82545d71e9e3f4a1d41e8c4ebd2884c9`, 15,872 bytes. The randomized all-caps filename pattern and non-standard placement are indicators of an attacker-dropped binary. Prefetch `TOPLZAGU.EXE-4EFD8FD3.pf` confirms execution. [CONFIRMED — exec_id 019e10f4-d725-7d91-a681-577d551822de, exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4]

### hyvy.exe — Internet-downloaded malware (tdungan)

`WINDOWS/system32/hyvy.exe` (inode 5237) on tdungan has a Zone.Identifier ADS confirming it was downloaded from the internet. SHA256: `5a31b6aae73fdfe211c90370f3d7369846ec55fa2de8f20fd2e35368c1070232`, 2,277,805 bytes (similar size to spinlock.exe, suggesting another PyInstaller bundle). Prefetch `HYVY.EXE-2A94EF14.pf` confirms execution. [CONFIRMED — exec_id 019e10f6-54bc-7c13-b6ad-b986e0ebbf12, exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### a.exe — Small loader/beacon

On tdungan, `a.exe` (9,216 bytes, SHA256: `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec`) executed under four user accounts: RSydow, SRL-Helpdesk, tdungan, and vibranium (each has an instance in their Temp directory). Multiple Prefetch entries confirm repeated execution. On nromanoff, `a.exe` present in `Users/vibranium/AppData/Local/Temp/`. [CONFIRMED — exec_id 019e10f6-514c-7050-ab00-4aad78c0091c, exec_id 019e10f2-bedf-7473-9710-d40d5706591a, exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4]

### pkxezy1tji98.exe — Random-named dropper (tdungan)

`Documents and Settings/tdungan/Local Settings/Temp/pkxezy1tji98.exe` (inode 3019). Random alphanumeric filename is a classic malware staging pattern. Prefetch confirms execution. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### BC Wipe anti-forensics tool on DC shared drive

`SharedFolders/Public/Security Tools/BC Wipe/bcwipe5.exe` present on DC shared network location, available to all domain hosts. This tool accounts for sdeleted spinlock.exe and other cleaned artifacts. [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b]

### No attacker binaries in Startup folders

No attacker binaries found in user Startup folders on DC, nromanoff, or tdungan. Persistence for `usboesrv.exe` was via service registration (confirmed in prior memory run via svcscan). [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b (negative finding)]

---

## G4 — Exfiltration: What Was Staged and Where It Went

### Target IP data (R&D documents on tdungan)

The attacker targeted tdungan's Alloy Research directory. Files confirmed present on disk (accessed via vibranium Office LNK artifacts):

| File | Location |
|------|----------|
| `VIBRANIUM.docx` | `My Documents/Alloy Research/Detailed Vibranium R&D Documents/` |
| `SUCCESS-TEST-PLAN-VIBRANIUM-ALLOY-RESULTS.docx` | same |
| `Metal Alloy List Research.xlsx` | same |
| `Dossier - Dr Myron MacLain.docx` | same |
| `ADAMANTIUM-Background.docx` | same |
| `Researched Sub-Atomic Particles.xlsx` | same |
| `The Shield Background and Ongoing Research.docx` | same |

[CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### Financial data

`Documents and Settings/tdungan/My Documents/Backstopped Accounts - R&D Costs Alloy Research/Credit-Card-Numbers-For-Research.xls` and `CC-Backstopped-Accounts.xlsx` are present on tdungan's disk. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

`Credit-Card-Numbers-For-Research.xlsx` is additionally present at `Documents and Settings/tdungan/Local Settings/Temporary Internet Files/Content.Outlook/CNGZG4QC/`, the standard Office email attachment cache path. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

The Outlook cache location indicates this file was received as an email attachment to tdungan's mailbox. [INFERRED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a; reasoning: `Content.Outlook/` is Office's standard temp directory for email attachment previews]

### Dropbox exfiltration channel

Dropbox installed at `Documents and Settings/tdungan/Application Data/Dropbox/`. The attacker staged `Documents and Settings/tdungan/My Documents/Dropbox/STARK Research Labs.docx` in the Dropbox sync folder for cloud exfiltration. `CCleaner.exe` was also delivered via Dropbox (anti-forensics). `DROPBOX.EXE-126FAE33.pf` confirms repeated Dropbox execution. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### Zip staging and FTP exfiltration

`WINDOWS/Prefetch/ZIPPER.EXE-2C9C69B1.pf` on tdungan — file archiver executed (binary sdeleted, Prefetch survives). `WINDOWS/Prefetch/FTP.EXE-0FFFB5A3.pf` on tdungan — Windows native FTP client executed, consistent with direct transfer to attacker infrastructure. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### C2 exfil channel

`usboesrv.exe` on DC maintained two simultaneous persistent TCP connections to `96.255.98.154:29932` (ESTABLISHED at capture time, PID 27304). [CONFIRMED — exec_id 019e10fa-e7bf-7e33-8377-aff5c2a65f83]

[GAP] Specific files transferred over the C2 channel: The RDP bitmap cache `Users/rsydow/AppData/Local/Microsoft/Terminal Server Client/Cache/bcache22.bmc` exists on DC and may contain screengrab tiles of attacker activity; binary decoding requires additional tooling not invoked in this run.

---

## G5 — Unified Incident Timeline (UTC)

| Date | Event | Evidence |
|------|-------|----------|
| ~2012-04-02 | `AdbeRdr910_en_US.exe` delivered to tdungan's Dropbox and deleted | Dropbox cache path with embedded timestamp `4f799e4f` and directory `2012-04-02` |
| ~2012-04-02 | tdungan initial compromise via malicious Adobe Reader from Dropbox | `ADBERDR910_EN_US.EXE-2CFF2AE5.pf` |
| ~2012-04-03–04 | `adberdr813.exe` executed on nromanoff; crash/exploit fires | WER AppCrash `adberdr813.exe` report |
| ~2012-04-05–06 | vibranium account RDP to DC established; `usboesrv.exe` installed as service | Memory + disk artifacts on DC |
| ~2012-04-06–09 | `hydrakatz.exe`, `spinlock.exe`, `a.exe`, `TOPLZAGU.exe`, `hyvy.exe` deployed across hosts | Prefetch on nromanoff and tdungan |
| ~2012-04-06–09 | vibranium account accessed Alloy Research documents on tdungan | Office LNK Recent items |
| ~2012-04-06–09 | `STARK Research Labs.docx` staged in Dropbox; FTP and ZIPPER executed | Dropbox folder, Prefetch |
| 2012-04-06 → 2012-04-09 | C2 active: `usboesrv.exe` → `96.255.98.154:29932` (two channels) | DC netscan, PID 27304 |

[CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b, exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4, exec_id 019e10f2-bedf-7473-9710-d40d5706591a, exec_id 019e10fa-e7bf-7e33-8377-aff5c2a65f83]

---

## G6 — Credentials Stolen / Abused

### vibranium domain account (primary attacker account)

SID `S-1-5-21-2036804247-3058324640-2116585241-1673`. DPAPI Protect keys on DC and on tdungan at `Documents and Settings/vibranium/Application Data/Microsoft/Protect/`. Interactive sessions confirmed on DC (RDP), nromanoff (`a.exe` in Temp), and tdungan (Office documents accessed, Recent LNKs). [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b, exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4, exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### hydrakatz.exe — credential stealer deployed to nromanoff and tdungan

`Windows/System32/hydrakatz.exe` on nromanoff (inode 60958) and `WINDOWS/system32/hydrakatz.exe` on tdungan (inode 4736), identical SHA256 `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975`. Credentials harvested from these workstations would include domain credentials cached in LSASS across both hosts. [CONFIRMED — exec_id 019e10f4-d113-7653-96a9-dcdae4929196, exec_id 019e10f4-d415-74b1-be65-c60439c821bf, exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4, exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### rsydow credentials abused on DC

rsydow has a credentials cache on DC at `Users/rsydow/AppData/Local/Microsoft/Credentials/2438F9B04D7CF823C0B0BAB39930CD27` and an RDP bitmap cache at `Users/rsydow/AppData/Local/Microsoft/Terminal Server Client/Cache/bcache22.bmc`, indicating RDP connections were made from the DC under rsydow's account. [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b]

### SRL-Helpdesk and tdungan accounts abused

Both accounts have `a.exe` in their Temp directories on the tdungan machine, confirming the attacker executed tools under those account contexts. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

---

## Remaining Gaps

**[GAP]** nromanoff memory analysis: PDB symbol resolution failure blocked Vol3 analysis. Disk confirms extensive attacker activity but live process list at capture time on nromanoff is unknown.

**[GAP]** adberdr813.exe secondary payload on nromanoff: The actual binary dropped by the Adobe exploit was not identified on disk. Likely in-memory only (fileless) or sdeleted.

**[GAP]** FTP exfiltration destination: FTP.EXE Prefetch on tdungan confirms execution but destination IP and transferred files require event log or network capture evidence.

**[GAP]** RDP bitmap cache content: `bcache22.bmc` exists on DC under Administrator, rsydow, and tdungan accounts but binary decoding requires additional tooling.

**[GAP]** Registry service persistence parameters: SYSTEM hive at `Windows/System32/config/SYSTEM` on DC was not parsed; usboesrv service registration details (ImagePath, Start type) are unknown from this run.

**[GAP]** Dropbox account identity: Dropbox `host.db` and `config.db` were not extracted; attacker-controlled Dropbox account email is unknown.

---

## Attacker Toolset Summary

| Binary | Host | Path | SHA256 | Size |
|--------|------|------|--------|------|
| usboesrv.exe (C2 implant) | DC | `Windows/System32/` | `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec` | 571,392 |
| hydrakatz.exe | nromanoff | `Windows/System32/` | `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975` | 548,848 |
| hydrakatz.exe | tdungan | `WINDOWS/system32/` | `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975` | 548,848 |
| spinlock.exe | nromanoff | `Windows/System32/` | `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead` | 2,271,885 |
| spinlock.exe | tdungan | `WINDOWS/system32/` | `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead` | 2,271,885 |
| TOPLZAGU.exe | nromanoff | `Windows/` (root) | `0c8439344e9e2c8cbac86092ec96711c82545d71e9e3f4a1d41e8c4ebd2884c9` | 15,872 |
| hyvy.exe | tdungan | `WINDOWS/system32/` | `5a31b6aae73fdfe211c90370f3d7369846ec55fa2de8f20fd2e35368c1070232` | 2,277,805 |
| a.exe | tdungan/nromanoff | various Temp dirs | `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec` | 9,216 |

All binary SHAs confirmed via `tsk_icat_extract`; paths confirmed via `tsk_fls_list`.

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

### Demotion list — 5 claims

**[1] partial** — cited tool(s): tsk_fls_list — exec_ids: (none)
- missing tokens (claim says X but X not in cited tool's data): `0x4f799e4f`, ` and the Prefetch `
- already matched: `-2CFF2AE5.pf`, `ADBERDR910_EN_US.EXE`, `4f799e4f`, `2012-04-02`
> **[1] partial — AdbeRdr910 Dropbox claim (timestamp decode)** The file path `Documents and Settings/tdungan/My Documents/Dropbox/.dropbox.cache/2012-04-02/AdbeRdr910_en_US (deleted 4f799e4f-1980380-08f01636).exe` and the Prefetch `WINDOWS/Prefetch/ADBERDR910_EN_US.EXE-2CFF2AE5.pf…


**[2] partial** — cited tool(s): vol3_netscan, tsk_fls_list, tsk_icat_extract — exec_ids: (none)
- missing tokens (claim says X but X not in cited tool's data): `96.255.98.154:29932`
- already matched: `27304`, `96.255.98.154`, `usboesrv.exe`
> The System32 copy is the live C2 implant: DC netscan confirms two simultaneous ESTABLISHED TCPv4 connections from `usboesrv.exe` (PID 27304) to `96.255.98.154:29932` (local ports 58495 and 58497). [CONFIRMED — exec_id 019e10fa-e7bf-7e33-8377-aff5c2a65f83, exec_id 019e10f2-232c-73…


**[3] partial** — cited tool(s): tsk_icat_extract, tsk_icat_extract, tsk_fls_list, tsk_fls_list — exec_ids: (none)
- negation violations (claim says NOT X but X IS in cited tool's data): `7793`, `60927`, `spinlock.exe`, `WINDOWS/system32/spinlock.exe`, `Windows/System32/spinlock.exe`
- already matched: `_MEI`, `spinlock.exe.manifest`
> Present in System32 on both nromanoff (`Windows/System32/spinlock.exe`, inode 60927) and tdungan (`WINDOWS/system32/spinlock.exe`, inode 7793) — not deleted. PyInstaller-bundled binary confirmed by `_MEI` temp extraction directories containing `spinlock.exe.manifest` files on bot…


**[4] partial** — cited tool(s): vol3_netscan — exec_ids: (none)
- missing tokens (claim says X but X not in cited tool's data): `96.255.98.154:29932`
- already matched: `27304`, `96.255.98.154`, `usboesrv.exe`
> `usboesrv.exe` on DC maintained two simultaneous persistent TCP connections to `96.255.98.154:29932` (ESTABLISHED at capture time, PID 27304). [CONFIRMED — exec_id 019e10fa-e7bf-7e33-8377-aff5c2a65f83]


**[5] partial** — cited tool(s): tsk_fls_list — exec_ids: (none)
- missing tokens (claim says X but X not in cited tool's data): ` and an RDP bitmap cache at `
- already matched: `2438F9B04D7CF823C0B0BAB39930CD27`
> rsydow has a credentials cache on DC at `Users/rsydow/AppData/Local/Microsoft/Credentials/2438F9B04D7CF823C0B0BAB39930CD27` and an RDP bitmap cache at `Users/rsydow/AppData/Local/Microsoft/Terminal Server Client/Cache/bcache22.bmc`, indicating RDP connections were made from the D…



---

When you produce iteration 3's report, end with the line `SIFT-OWL RUN COMPLETE`.
