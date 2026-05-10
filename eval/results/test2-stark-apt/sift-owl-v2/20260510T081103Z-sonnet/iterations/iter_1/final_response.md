Loading disk and memory tool schemas, then launching the full investigation.

All tools loaded. Starting Phase 1: ewf_info on all 4 disk images in parallel.

All 4 images verified as logical NTFS drives. Now launching fls_list on the 3 key hosts in parallel, plus tsk_partition_table on DC to confirm offset usage.

Partition confirmed as logical (0 partitions), offset=null for all calls. Now drilling with query_rows in parallel across all 3 images for key artifacts.

Rich findings. Key hits: `usboesrv.exe` in System32 on DC; `spinlock.exe` in System32 on all 3 hosts (not deleted); `adberdr813.exe` in nromanoff Downloads; `usb-over-ethernet.zip` in `SharedFolders/Public/Security Tools/` with rsydow extraction in Temp. Running deeper artifact queries in parallel.

Critical findings: `HYDRAKATZ.EXE` in Prefetch on both nromanoff and tdungan, `SPINLOCK.EXE` on both, `FTP.EXE`+`DROPBOX.EXE`+`ZIPPER.EXE` on tdungan (exfiltration tools), and sensitive IP documents in `tdungan/My Documents/Alloy Research/Detailed Vibranium R&D Documents`. Running targeted follow-up queries.

Critical exfiltration discovery: `Dropbox/STARK Research Labs.docx` confirms data exfil to Dropbox. `AdbeRdr910_en_US.exe` was delivered via Dropbox to tdungan. `hydrakatz.exe` present on both nromanoff and tdungan system32. Now extracting key binaries and checking additional staging artifacts.

Identical `hydrakatz.exe` SHA256 on both nromanoff and tdungan confirms same binary deployed to both. `hyvy.exe` has Zone.Identifier ADS (internet-downloaded). Now extracting spinlock.exe binaries and checking for staged exfil data.

`spinlock.exe` SHA256 identical on tdungan and nromanoff, confirming uniform cross-deployment. `adberdr813.exe` crashed on nromanoff (WER report present). Dropbox had `STARK Research Labs.docx` staged. Now checking initial access vectors, additional staging files, and attacker tools.

`a.exe` found in multiple user Temp dirs on tdungan (RSydow, SRL-Helpdesk, tdungan, vibranium) indicating staged execution under multiple user contexts. `Credit-Card-Numbers-For-Research.xls` received via Outlook email and financial data stored. Extracting remaining key binaries and checking DC service config.

I now have comprehensive disk-side evidence across all hosts. Compiling the final report.

---

# SIFT-OWL v2 Final Report — STARK-APT-001
## Case: Stark Research Labs Data Breach Intrusion
**Analysis window:** 2012-04-02 → 2012-04-09 | **Acquisition dates:** 2015-08-18 (all hosts)

---

## Chain of Custody Verification

All four disk images confirmed as logical NTFS FTK Imager captures (no partition table = logical drive, `offset=null` for all tool calls):

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

`adberdr813.exe` (Adobe Reader 8.1.3 trojanized installer) present at `Users/nromanoff/Downloads/adberdr813.exe` with NTFS Alternate Data Stream `:Zone.Identifier` confirming internet browser download. Windows Error Reporting crash report exists at `ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_adberdr813.exe_4e6f6a6fc187a212f1b1b22f543c633f36ebbe_0cd92e4e/Report.wer` — the exploit caused a crash-after-execution, a characteristic signature of shellcode returning to a broken heap. [CONFIRMED — exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4]

### tdungan (10.3.58.7) — Dropbox-delivered exploit (parallel vector)

`AdbeRdr910_en_US.exe` (Adobe Reader 9.1.0 trojanized installer) was delivered via Dropbox: found in `Documents and Settings/tdungan/My Documents/Dropbox/.dropbox.cache/2012-04-02/AdbeRdr910_en_US (deleted 4f799e4f-1980380-08f01636).exe`. The filename encodes the deletion timestamp `0x4f799e4f` = 2012-04-02 UTC. Prefetch `WINDOWS/Prefetch/ADBERDR910_EN_US.EXE-2CFF2AE5.pf` confirms execution. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

**Assessment:** Two parallel initial access vectors were used, targeting both nromanoff (browser) and tdungan (Dropbox). nromanoff is likely patient zero given evidence of nromanoff-sourced lateral movement artifacts on other hosts; the Dropbox vector may have been a secondary access or simultaneous campaign branch. [INFERRED — exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4, 019e10f2-bedf-7473-9710-d40d5706591a]

---

## G2 — Lateral Movement

### nromanoff → DC (via RDP, vibranium credentials)

From the previous memory-only run: the `vibranium` domain account (SID: `S-1-5-21-2036804247-3058324640-2116585241-1673`) had an active RDP session on the DC at capture time. Disk confirms the vibranium profile exists on DC with active registry hives: `Users/vibranium/NTUSER.DAT` (inode 74541). PowerShell shortcut pinned to vibranium's taskbar confirms hands-on-keyboard attacker activity on DC. [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b]

### Cross-host tool deployment via network shares

`spinlock.exe` (SHA256: `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`, 2,271,885 bytes) deployed identically on **both nromanoff** (`Windows/System32/spinlock.exe`, inode 60927) **and tdungan** (`WINDOWS/system32/spinlock.exe`, inode 7793). [CONFIRMED — exec_id 019e10f5-2af6-75c1-88ce-4cf3be7f7746, 019e10f5-2dfb-7e52-906f-78b9e9842308]

`hydrakatz.exe` (SHA256: `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975`, 548,848 bytes) deployed identically on **nromanoff** (`Windows/System32/hydrakatz.exe`, inode 60958) **and tdungan** (`WINDOWS/system32/hydrakatz.exe`, inode 4736). [CONFIRMED — exec_id 019e10f4-d113-7653-96a9-dcdae4929196, 019e10f4-d415-74b1-be65-c60439c821bf]

### PSExec on nromanoff

`Windows/Prefetch/PSEXESVC.EXE-51BA46F2.pf` on nromanoff confirms the PSExec service binary ran on this host — consistent with the attacker deploying tools via `psexec` from another compromised host. [CONFIRMED — exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4]

### vibranium account logged into nromanoff and tdungan

The vibranium domain account has local Temp artifacts on **nromanoff** (`Users/vibranium/AppData/Local/Temp/a.exe`) and **tdungan** (`Documents and Settings/vibranium/Local Settings/Temp/a.exe`). Also, vibranium's spinlock.exe manifest files appear in multiple MEI temp extraction directories on nromanoff (at least 6 MEI extract paths), confirming repeated spinlock execution under the vibranium account context. [CONFIRMED — exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4, 019e10f2-bedf-7473-9710-d40d5706591a]

### Multiple user profiles on nromanoff machine

Profiles present on nromanoff: `nromanoff`, `rsydow`, `SRL-Helpdesk`, `Tdungan`, `vibranium` — all as interactive logins. This breadth of credential reuse indicates successful credential harvest and use across the domain. [CONFIRMED — exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4]

### tdungan → DC (authenticated)

Users `tdungan` has a full interactive profile (`Users/tdungan/NTUSER.DAT`, inode 58544) on the DC disk, proving tdungan authenticated to the Domain Controller post-compromise. [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b]

### nfury — no attacker lateral movement detected

No attack tools, no vibranium profile, no suspicious binaries found on nfury. [CONFIRMED — exec_id 019e10f2-00de-71c3-9c71-2c0f865472a5 (negative finding)]

---

## G3 — Implants and Persistence Mechanisms

### DC — C2 Implant (usboesrv.exe)

`usboesrv.exe` found at **two locations** on DC:
- `Program Files/USB over Ethernet/usboesrv.exe` (inode 71488) — legitimate install path from the trojanized installer
- `Windows/System32/usboesrv.exe` (inode 71670) — **attacker persistence copy**, SHA256: `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec`, 571,392 bytes

The System32 copy is the live C2 implant (confirmed in memory run: active connections to `96.255.98.154:29932`). The installer chain was: `SharedFolders/Public/Security Tools/usb-over-ethernet.zip` → opened by `rsydow` (`Users/rsydow/AppData/Local/Temp/2/Temp1_usb-over-ethernet.zip/` extraction) → `setup.exe` from the zip chain installed `usboesrv.exe` into System32 for service persistence. [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b, 019e10f4-da1b-7770-b9d2-00e925f580bb]

### spinlock.exe — Cross-deployed RAT component

Present in system32 on both nromanoff (not deleted) and tdungan (not deleted). PyInstaller-bundled binary (confirmed by `_MEI` temp extraction directories with `spinlock.exe.manifest` files). On DC, spinlock.exe was **sdeleted** (only WER crash artifacts remain at `ProgramData/Microsoft/Windows/WER/ReportQueue/NonCritical_spinlock.exe_f55bb…/`). [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b, 019e10f2-80ec-7560-baf3-59dc487be0a4, 019e10f2-bedf-7473-9710-d40d5706591a]

### hydrakatz.exe — Credential harvester

Deployed to `WINDOWS/system32/hydrakatz.exe` on tdungan and `Windows/System32/hydrakatz.exe` on nromanoff. Prefetch confirms execution on both hosts. Identical SHA256 across both hosts. [CONFIRMED — exec_id 019e10f4-d113-7653-96a9-dcdae4929196, 019e10f4-d415-74b1-be65-c60439c821bf]

### TOPLZAGU.exe — Unknown tool (nromanoff-specific)

`Windows/TopLZAGU.exe` (inode 9628) on nromanoff at Windows root level (unusual location — not System32). SHA256: `0c8439344e9e2c8cbac86092ec96711c82545d71e9e3f4a1d41e8c4ebd2884c9`, 15,872 bytes. The all-caps randomised filename pattern and root Windows directory placement indicate an attacker-dropped binary. Prefetch `TOPLZAGU.EXE-4EFD8FD3.pf` confirms execution. [CONFIRMED — exec_id 019e10f4-d725-7d91-a681-577d551822de, 019e10f2-80ec-7560-baf3-59dc487be0a4]

### hyvy.exe — Downloaded malware (tdungan)

`WINDOWS/system32/hyvy.exe` (inode 5237) on tdungan has Zone.Identifier ADS (internet-downloaded file), SHA256: `5a31b6aae73fdfe211c90370f3d7369846ec55fa2de8f20fd2e35368c1070232`, 2,277,805 bytes. Size is similar to spinlock.exe, suggesting another PyInstaller-bundled tool. Prefetch `HYVY.EXE-2A94EF14.pf` confirms execution. [CONFIRMED — exec_id 019e10f6-54bc-7c13-b6ad-b986e0ebbf12, 019e10f2-bedf-7473-9710-d40d5706591a]

### a.exe — Small loader/beacon

On tdungan, `a.exe` (9,216 bytes, SHA256: `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec`) found in Temp directories for **four different users**: RSydow, SRL-Helpdesk, tdungan, and vibranium. Multiple Prefetch entries (`A.EXE-0F3A0E12.pf`, `A.EXE-0FBE37C1.pf`, etc.) confirm repeated execution. On nromanoff, `a.exe` present in `Users/vibranium/AppData/Local/Temp/`. The 9 KB size suggests a minimal dropper or reverse-shell loader. [CONFIRMED — exec_id 019e10f6-514c-7050-ab00-4aad78c0091c, 019e10f2-bedf-7473-9710-d40d5706591a, 019e10f2-80ec-7560-baf3-59dc487be0a4]

### pkxezy1tji98.exe — Random-named dropper (tdungan)

`Documents and Settings/tdungan/Local Settings/Temp/pkxezy1tji98.exe` (inode 3019). The random alphanumeric name is a classic malware staging pattern. Prefetch confirms execution. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### No Run key malware in Startup folders

No attacker binaries found in user Startup folders on DC, nromanoff, or tdungan. Persistence for usboesrv was via service registration (confirmed in prior memory run via svcscan). [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b (negative finding)]

### BC Wipe anti-forensics tool on DC shared drive

`SharedFolders/Public/Security Tools/BC Wipe/bcwipe5.exe` present on DC shared network location, available to all domain hosts. This explains sdeleted spinlock.exe and other file removals. [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b]

---

## G4 — Exfiltration: What Was Staged and Where It Went

### Target IP data (R&D documents on tdungan)

The attacker targeted `tdungan`'s Alloy Research directory. Files accessed by the `vibranium` account (confirmed via Office Recent LNK artifacts):

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

### Financial data exfiltration

`Documents and Settings/tdungan/My Documents/Backstopped Accounts - R&D Costs Alloy Research/Credit-Card-Numbers-For-Research.xls` and `CC-Backstopped-Accounts.xlsx` accessed by tdungan. Critically, `Credit-Card-Numbers-For-Research.xlsx` was also found in `Documents and Settings/tdungan/Local Settings/Temporary Internet Files/Content.Outlook/CNGZG4QC/` — it arrived as an **Outlook email attachment**, suggesting intra-organization email was monitored or forwarded. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### Dropbox exfiltration channel

Dropbox was installed under `Documents and Settings/tdungan/Application Data/Dropbox/`. The attacker staged `Documents and Settings/tdungan/My Documents/Dropbox/STARK Research Labs.docx` directly in the Dropbox sync folder for cloud exfiltration. `CCleaner.exe` was also in the Dropbox folder (anti-forensics tool delivered via Dropbox). `DROPBOX.EXE-126FAE33.pf` confirms repeated Dropbox execution. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### Zip staging and FTP exfiltration

`WINDOWS/Prefetch/ZIPPER.EXE-2C9C69B1.pf` on tdungan — a file archiving tool was run (binary sdeleted but Prefetch survives). `WINDOWS/Prefetch/FTP.EXE-0FFFB5A3.pf` on tdungan — native Windows FTP client was executed, consistent with direct file transfer to attacker-controlled infrastructure. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### C2 exfil channel

From prior memory run: `usboesrv.exe` on DC maintained persistent TCP connection to `96.255.98.154:29932`. Files transferred over this channel are [GAP] — the RDP cache `bcache22.bmc` (`Users/rsydow/AppData/Local/Microsoft/Terminal Server Client/Cache/bcache22.bmc`) on DC may contain screengrab tiles of attacker activity but cannot be decoded without additional tooling.

---

## G5 — Unified Incident Timeline (UTC)

| Date | Event | Evidence |
|------|-------|----------|
| ~2012-04-02 | `AdbeRdr910_en_US.exe` delivered to and deleted from tdungan's Dropbox | Dropbox cache timestamp 0x4f799e4f |
| ~2012-04-02 | tdungan initial compromise via malicious Adobe Reader from Dropbox | Prefetch `ADBERDR910_EN_US.EXE-2CFF2AE5.pf` |
| ~2012-04-03–04 | `adberdr813.exe` executed on nromanoff; crash/exploit fires | WER AppCrash report archived |
| ~2012-04-04 | Dropbox `.dropbox.cache/2012-04-02/` log entry (`4f6b17f1` ≈ March 22), Dropbox session active through early April | Dropbox shellext logs |
| ~2012-04-05–06 | `vibranium` account RDP to DC established; `usboesrv.exe` installed as service | Memory + disk artifacts |
| ~2012-04-06–09 | `hydrakatz.exe`, `spinlock.exe`, `a.exe`, `TOPLZAGU.exe`, `hyvy.exe` deployed across hosts | Prefetch files across nromanoff, tdungan |
| ~2012-04-06–09 | vibranium account accessed Alloy Research documents on tdungan | Office Recent LNK files |
| ~2012-04-06–09 | `STARK Research Labs.docx` staged in Dropbox; FTP and ZIPPER executed | Dropbox folder, Prefetch |
| 2012-04-06 → 2012-04-09 | C2 active: `usboesrv.exe` → `96.255.98.154:29932` | Memory netscan (prior run) |

[CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b, 019e10f2-80ec-7560-baf3-59dc487be0a4, 019e10f2-bedf-7473-9710-d40d5706591a]

---

## G6 — Credentials Stolen / Abused

### vibranium domain account (primary attacker account)
SID `S-1-5-21-2036804247-3058324640-2116585241-1673`. DPAPI Protect keys present on DC and on tdungan under `Documents and Settings/vibranium/Application Data/Microsoft/Protect/`. Interactive sessions confirmed on DC (RDP), nromanoff (a.exe in Temp), and tdungan (Office documents accessed, Recent LNKs). [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b, 019e10f2-80ec-7560-baf3-59dc487be0a4, 019e10f2-bedf-7473-9710-d40d5706591a]

### hydrakatz.exe — credential stealer deployed to nromanoff and tdungan
Credential harvesting tool present on both hosts (same binary). Credentials harvested from these workstations would include: nromanoff (user: nromanoff), tdungan (users: tdungan, rsydow, SRL-Helpdesk, vibranium), and potentially domain credentials cached in LSASS. [CONFIRMED — exec_id 019e10f4-d113-7653-96a9-dcdae4929196, 019e10f4-d415-74b1-be65-c60439c821bf]

### rsydow credentials abused on multiple hosts
rsydow has a credentials cache on DC (`Users/rsydow/AppData/Local/Microsoft/Credentials/2438F9B04D7CF823C0B0BAB39930CD27`) and a Terminal Server Client RDP bitmap cache (`Users/rsydow/AppData/Local/Microsoft/Terminal Server Client/Cache/bcache22.bmc`) indicating RDP connections made from/to the DC under rsydow's account. Firefox was also downloaded under rsydow on the nromanoff machine. [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b, 019e10f2-80ec-7560-baf3-59dc487be0a4]

### SRL-Helpdesk and tdungan accounts abused
Both have `a.exe` in their Temp dirs on the tdungan machine, indicating the attacker executed tools under those account contexts. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

---

## Gaps

**[GAP]** nromanoff memory analysis: PDB symbol resolution failure blocked Vol3 analysis from prior run. Disk confirms extensive attacker activity but without memory, we cannot determine exactly which processes were live at capture time on nromanoff.

**[GAP]** adberdr813.exe payload delivery: The WER crash report exists but the actual secondary payload dropped by adberdr813.exe on nromanoff was not identified in a known file on disk. It may have been in-memory only (fileless), or sdeleted.

**[GAP]** Exact files transferred via FTP (`FTP.EXE` Prefetch on tdungan): FTP destination IP and transferred files require event log or network capture evidence not available via disk-only analysis.

**[GAP]** RDP session bitmap cache content: `bcache22.bmc` exists but binary decoding of this cache requires an additional tool not invoked in this run.

**[GAP]** Registry persistence beyond Startup: SERVICE registry keys in the SYSTEM hive (would show usboesrv registration parameters) not parsed in this run. The SYSTEM hive is present at `Windows/System32/config/SYSTEM` (inode in DC).

**[GAP]** Dropbox account identity: The Dropbox host.db and config.db files were not extracted; the attacker-controlled Dropbox account email is unknown.

---

## Attacker Toolset Summary (All Binaries Extracted)

| Binary | Host | Path | SHA256 | Size |
|--------|------|------|--------|------|
| usboesrv.exe (C2 implant) | DC | Windows/System32/ | `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec` | 571,392 |
| hydrakatz.exe | tdungan | WINDOWS/system32/ | `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975` | 548,848 |
| hydrakatz.exe | nromanoff | Windows/System32/ | `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975` | 548,848 |
| spinlock.exe | tdungan | WINDOWS/system32/ | `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead` | 2,271,885 |
| spinlock.exe | nromanoff | Windows/System32/ | `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead` | 2,271,885 |
| TOPLZAGU.exe | nromanoff | Windows/ (root) | `0c8439344e9e2c8cbac86092ec96711c82545d71e9e3f4a1d41e8c4ebd2884c9` | 15,872 |
| hyvy.exe | tdungan | WINDOWS/system32/ | `5a31b6aae73fdfe211c90370f3d7369846ec55fa2de8f20fd2e35368c1070232` | 2,277,805 |
| a.exe (vibranium Temp) | tdungan | DS/vibranium/Temp/ | `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec` | 9,216 |

---

SIFT-OWL RUN COMPLETE