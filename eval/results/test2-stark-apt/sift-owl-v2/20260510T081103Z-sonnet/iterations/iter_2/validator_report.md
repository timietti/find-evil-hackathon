# Validator Report — iter_2

## Summary

- Total tagged claims:        **48**
  - CONFIRMED:                 36
  - INFERRED:                  5
  - HYPOTHESIS:                0
  - GAP:                       7
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           26 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                5 (some tokens found, some missing)
- ❌ failed:                 0 (no tokens found)
- ❓ unverifiable:           5 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           0 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 72.2%** (26 verified / 36 confirmed)

## Per-claim verdicts

### ⚠ partial _(line 29)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `-2CFF2AE5.pf`, `ADBERDR910_EN_US.EXE`, `4f799e4f`, `2012-04-02`
- **missing**: `0x4f799e4f`, ` and the Prefetch `
- claim: > **[1] partial — AdbeRdr910 Dropbox claim (timestamp decode)** The file path `Documents and Settings/tdungan/My Documents/Dropbox/.dropbox.cache/2012-04-02/AdbeRdr910_en_US (deleted 4f799e4f-1980380-08…

### ❓ unverifiable _(line 75)_
- exec_ids: `56eb712b06e2`, `2e25aa9a719c`, `2c0f865472a5`, `efacda3f01c5`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e10f1-fc74-7ba1-9cd4-56eb712b06e2, 019e10f1-ff4f-7d71-b106-2e25aa9a719c, 019e10f2-00de-71c3-9c71-2c0f865472a5, 019e10f2-02bb-7842-a5dd-efacda3f01c5]

### ✅ verified _(line 83)_
- tools: `tsk_fls_list`
- exec_ids: `59dc487be0a4`
- matched: `adberdr813.exe`, `:Zone.Identifier`, `Users/nromanoff/Downloads/adberdr813.exe`
- claim: > `adberdr813.exe` (Adobe Reader 8.1.3 trojanized installer) present at `Users/nromanoff/Downloads/adberdr813.exe` with NTFS Alternate Data Stream `:Zone.Identifier` confirming internet browser download…

### ✅ verified _(line 87)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `AdbeRdr910_en_US.exe`
- claim: > `AdbeRdr910_en_US.exe` (Adobe Reader 9.1.0 trojanized installer) was delivered via Dropbox and logged in the Dropbox cache: `Documents and Settings/tdungan/My Documents/Dropbox/.dropbox.cache/2012-04-…

### ✅ verified _(line 89)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `-2CFF2AE5.pf`, `ADBERDR910_EN_US.EXE`, `WINDOWS/Prefetch/ADBERDR910_EN_US.EXE-2CFF2AE5.pf`
- claim: > Prefetch `WINDOWS/Prefetch/ADBERDR910_EN_US.EXE-2CFF2AE5.pf` confirms execution. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### ✅ verified _(line 101)_
- tools: `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`
- matched: `74541`, `NTUSER.DAT`, `vibranium`, `S-1-5-21-2036804247-3058324640-2116585241-1673`, `Users/vibranium/NTUSER.DAT`
- claim: > The `vibranium` domain account (SID: `S-1-5-21-2036804247-3058324640-2116585241-1673`) had an active RDP session on the DC at capture time (established from prior memory run). Disk confirms the vibran…

### ✅ verified _(line 105)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `4cf3be7f7746`, `78b9e9842308`, `59dc487be0a4`, `d40d5706591a`
- matched: `7793`, `60927`, `spinlock.exe`, `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`, `WINDOWS/system32/spinlock.exe`, `Windows/System32/spinlock.exe`
- claim: > `spinlock.exe` (SHA256: `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`, 2,271,885 bytes) deployed identically to **nromanoff** at `Windows/System32/spinlock.exe` (inode 60927) and …

### ✅ verified _(line 107)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `dcdae4929196`, `c60439c821bf`, `59dc487be0a4`, `d40d5706591a`
- matched: `60958`, `4736`, `hydrakatz.exe`, `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975`, `WINDOWS/system32/hydrakatz.exe`, `Windows/System32/hydrakatz.exe`
- claim: > `hydrakatz.exe` (SHA256: `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975`, 548,848 bytes) deployed identically to **nromanoff** at `Windows/System32/hydrakatz.exe` (inode 60958) and …

### ✅ verified _(line 111)_
- tools: `tsk_fls_list`
- exec_ids: `59dc487be0a4`
- matched: `PSEXESVC.EXE`, `-51BA46F2.pf`, `Windows/Prefetch/PSEXESVC.EXE-51BA46F2.pf`
- claim: > `Windows/Prefetch/PSEXESVC.EXE-51BA46F2.pf` on nromanoff confirms the PSExec service binary was executed on this host. [CONFIRMED — exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4]

### ✅ verified _(line 117)_
- tools: `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `59dc487be0a4`, `d40d5706591a`
- matched: `a.exe`, `Temp`, `Documents and Settings/vibranium/Local Settings/Temp/a.exe`, `Users/vibranium/AppData/Local/Temp/a.exe`
- claim: > The vibranium domain account's `Temp` directory contains `a.exe` on both **nromanoff** (`Users/vibranium/AppData/Local/Temp/a.exe`) and **tdungan** (`Documents and Settings/vibranium/Local Settings/Te…

### ✅ verified _(line 121)_
- tools: `tsk_fls_list`
- exec_ids: `59dc487be0a4`
- matched: `Tdungan`, `rsydow`, `nromanoff`, `SRL-Helpdesk`, `vibranium`
- claim: > Profiles present on nromanoff: `nromanoff`, `rsydow`, `SRL-Helpdesk`, `Tdungan`, `vibranium` — all as interactive logins. This breadth indicates successful credential harvest and reuse across the doma…

### ✅ verified _(line 125)_
- tools: `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`
- matched: `58544`, `NTUSER.DAT`, `Users/tdungan/NTUSER.DAT`
- claim: > `Users/tdungan/NTUSER.DAT` (inode 58544) is present on the DC disk, proving tdungan authenticated to the Domain Controller post-compromise. [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b]

### ❓ unverifiable _(line 129)_
- exec_ids: `2c0f865472a5`
- note: claim has no extractable tokens (prose only)
- claim: > No attack tools, no vibranium profile, no suspicious binaries found on nfury. [CONFIRMED — exec_id 019e10f2-00de-71c3-9c71-2c0f865472a5 (negative finding)]

### ❓ unverifiable _(line 141)_
- exec_ids: `e9e4fe2b1f8b`, `00e925f580bb`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b, exec_id 019e10f4-da1b-7770-b9d2-00e925f580bb]

### ⚠ partial _(line 143)_
- tools: `vol3_netscan`, `tsk_fls_list`, `tsk_icat_extract`
- exec_ids: `aff5c2a65f83`, `e9e4fe2b1f8b`, `00e925f580bb`
- matched: `27304`, `96.255.98.154`, `usboesrv.exe`
- **missing**: `96.255.98.154:29932`
- claim: > The System32 copy is the live C2 implant: DC netscan confirms two simultaneous ESTABLISHED TCPv4 connections from `usboesrv.exe` (PID 27304) to `96.255.98.154:29932` (local ports 58495 and 58497). [CO…

### ✅ verified _(line 145)_
- tools: `tsk_fls_list`, `tsk_icat_extract`
- exec_ids: `e9e4fe2b1f8b`, `00e925f580bb`
- matched: `usb-over-ethernet.zip`, `setup.exe`, `Temp1_usb-over-ethernet.zip`, `usboesrv.exe`, `Users/rsydow/AppData/Local/Temp/2/Temp1_usb-over-ethernet.zip/`, `rsydow`, `SharedFolders/Public/Security Tools/usb-over-ethernet.zip`
- claim: > Installer chain: `SharedFolders/Public/Security Tools/usb-over-ethernet.zip` → extracted by `rsydow` to `Users/rsydow/AppData/Local/Temp/2/Temp1_usb-over-ethernet.zip/` → `setup.exe` from the zip inst…

### ⚠ partial _(line 149)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `4cf3be7f7746`, `78b9e9842308`, `59dc487be0a4`, `d40d5706591a`
- matched: `_MEI`, `spinlock.exe.manifest`
- 🚨 negation violations (claimed absent but found): `7793`, `60927`, `spinlock.exe`, `WINDOWS/system32/spinlock.exe`, `Windows/System32/spinlock.exe`
- claim: > Present in System32 on both nromanoff (`Windows/System32/spinlock.exe`, inode 60927) and tdungan (`WINDOWS/system32/spinlock.exe`, inode 7793) — not deleted. PyInstaller-bundled binary confirmed by `_…

### ✅ verified _(line 151)_
- tools: `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`
- matched: `spinlock.exe`
- claim: > On DC, spinlock.exe was sdeleted. WER crash artifacts survive at `ProgramData/Microsoft/Windows/WER/ReportQueue/NonCritical_spinlock.exe_f55bbffa8ebc6a99e6cbf535420484d134edcb1_cab_436b9004/Report.wer…

### ✅ verified _(line 155)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `dcdae4929196`, `c60439c821bf`, `59dc487be0a4`, `d40d5706591a`
- matched: `60958`, `4736`, `-27B49502.pf`, `-A0DADA85.pf`, `HYDRAKATZ.EXE`, `hydrakatz.exe`, `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975`, `WINDOWS/system32/hydrakatz.exe` (+3 more)
- claim: > Deployed to `Windows/System32/hydrakatz.exe` on nromanoff (inode 60958) and `WINDOWS/system32/hydrakatz.exe` on tdungan (inode 4736). Identical SHA256 `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d…

### ✅ verified _(line 159)_
- tools: `tsk_icat_extract`, `tsk_fls_list`
- exec_ids: `577d551822de`, `59dc487be0a4`
- matched: `9628`, `TOPLZAGU.EXE`, `-4EFD8FD3.pf`, `TopLZAGU.exe`, `0c8439344e9e2c8cbac86092ec96711c82545d71e9e3f4a1d41e8c4ebd2884c9`, `Windows/TopLZAGU.exe`, `TOPLZAGU.EXE-4EFD8FD3.pf`
- claim: > `Windows/TopLZAGU.exe` (inode 9628) on nromanoff is located in the Windows root directory, a placement outside the standard System32 location used by legitimate OS components. SHA256: `0c8439344e9e2c8…

### ✅ verified _(line 163)_
- tools: `tsk_icat_extract`, `tsk_fls_list`
- exec_ids: `b986e0ebbf12`, `d40d5706591a`
- matched: `5237`, `spinlock.exe`, `HYVY.EXE`, `hyvy.exe`, `-2A94EF14.pf`, `5a31b6aae73fdfe211c90370f3d7369846ec55fa2de8f20fd2e35368c1070232`, `WINDOWS/system32/hyvy.exe`, `HYVY.EXE-2A94EF14.pf`
- claim: > `WINDOWS/system32/hyvy.exe` (inode 5237) on tdungan has a Zone.Identifier ADS confirming it was downloaded from the internet. SHA256: `5a31b6aae73fdfe211c90370f3d7369846ec55fa2de8f20fd2e35368c1070232`…

### ✅ verified _(line 167)_
- tools: `tsk_icat_extract`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `4aad78c0091c`, `d40d5706591a`, `59dc487be0a4`
- matched: `a.exe`, `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec`, `Users/vibranium/AppData/Local/Temp/`
- claim: > On tdungan, `a.exe` (9,216 bytes, SHA256: `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec`) executed under four user accounts: RSydow, SRL-Helpdesk, tdungan, and vibranium (each has …

### ✅ verified _(line 171)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `3019`, `pkxezy1tji98.exe`, `Documents and Settings/tdungan/Local Settings/Temp/pkxezy1tji98.exe`
- claim: > `Documents and Settings/tdungan/Local Settings/Temp/pkxezy1tji98.exe` (inode 3019). Random alphanumeric filename is a classic malware staging pattern. Prefetch confirms execution. [CONFIRMED — exec_id…

### ✅ verified _(line 175)_
- tools: `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`
- matched: `spinlock.exe`, `bcwipe5.exe`, `SharedFolders/Public/Security Tools/BC Wipe/bcwipe5.exe`
- claim: > `SharedFolders/Public/Security Tools/BC Wipe/bcwipe5.exe` present on DC shared network location, available to all domain hosts. This tool accounts for sdeleted spinlock.exe and other cleaned artifacts…

### ✅ verified _(line 179)_
- tools: `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`
- matched: `usboesrv.exe`
- claim: > No attacker binaries found in user Startup folders on DC, nromanoff, or tdungan. Persistence for `usboesrv.exe` was via service registration (confirmed in prior memory run via svcscan). [CONFIRMED — e…

### ❓ unverifiable _(line 199)_
- exec_ids: `d40d5706591a`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### ✅ verified _(line 203)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `CC-Backstopped-Accounts.xlsx`, `Credit-Card-Numbers-For-Research.xls`, ` and `
- claim: > `Documents and Settings/tdungan/My Documents/Backstopped Accounts - R&D Costs Alloy Research/Credit-Card-Numbers-For-Research.xls` and `CC-Backstopped-Accounts.xlsx` are present on tdungan's disk. [CO…

### ✅ verified _(line 205)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `Credit-Card-Numbers-For-Research.xlsx`
- claim: > `Credit-Card-Numbers-For-Research.xlsx` is additionally present at `Documents and Settings/tdungan/Local Settings/Temporary Internet Files/Content.Outlook/CNGZG4QC/`, the standard Office email attachm…

### ✅ verified _(line 211)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `CCleaner.exe`, `Labs.docx`, `DROPBOX.EXE`, `-126FAE33.pf`, `Documents and Settings/tdungan/My Documents/Dropbox/STARK Research Labs.docx`, `Documents and Settings/tdungan/Application Data/Dropbox/`, `DROPBOX.EXE-126FAE33.pf`
- claim: > Dropbox installed at `Documents and Settings/tdungan/Application Data/Dropbox/`. The attacker staged `Documents and Settings/tdungan/My Documents/Dropbox/STARK Research Labs.docx` in the Dropbox sync …

### ✅ verified _(line 215)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `-0FFFB5A3.pf`, `ZIPPER.EXE`, `-2C9C69B1.pf`, `FTP.EXE`, `WINDOWS/Prefetch/FTP.EXE-0FFFB5A3.pf`, `WINDOWS/Prefetch/ZIPPER.EXE-2C9C69B1.pf`
- claim: > `WINDOWS/Prefetch/ZIPPER.EXE-2C9C69B1.pf` on tdungan — file archiver executed (binary sdeleted, Prefetch survives). `WINDOWS/Prefetch/FTP.EXE-0FFFB5A3.pf` on tdungan — Windows native FTP client execut…

### ⚠ partial _(line 219)_
- tools: `vol3_netscan`
- exec_ids: `aff5c2a65f83`
- matched: `27304`, `96.255.98.154`, `usboesrv.exe`
- **missing**: `96.255.98.154:29932`
- claim: > `usboesrv.exe` on DC maintained two simultaneous persistent TCP connections to `96.255.98.154:29932` (ESTABLISHED at capture time, PID 27304). [CONFIRMED — exec_id 019e10fa-e7bf-7e33-8377-aff5c2a65f83…

### ❓ unverifiable _(line 238)_
- exec_ids: `e9e4fe2b1f8b`, `59dc487be0a4`, `d40d5706591a`, `aff5c2a65f83`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b, exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4, exec_id 019e10f2-bedf-7473-9710-d40d5706591a, exec_id 019e10fa-e7bf-7e33-8377-aff5c2a65f83]

### ✅ verified _(line 246)_
- tools: `tsk_fls_list`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`, `59dc487be0a4`, `d40d5706591a`
- matched: `a.exe`, `S-1-5-21-2036804247-3058324640-2116585241-1673`, `Documents and Settings/vibranium/Application Data/Microsoft/Protect/`
- claim: > SID `S-1-5-21-2036804247-3058324640-2116585241-1673`. DPAPI Protect keys on DC and on tdungan at `Documents and Settings/vibranium/Application Data/Microsoft/Protect/`. Interactive sessions confirmed …

### ✅ verified _(line 250)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `dcdae4929196`, `c60439c821bf`, `59dc487be0a4`, `d40d5706591a`
- matched: `60958`, `4736`, `hydrakatz.exe`, `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975`, `WINDOWS/system32/hydrakatz.exe`, `Windows/System32/hydrakatz.exe`
- claim: > `Windows/System32/hydrakatz.exe` on nromanoff (inode 60958) and `WINDOWS/system32/hydrakatz.exe` on tdungan (inode 4736), identical SHA256 `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a…

### ⚠ partial _(line 254)_
- tools: `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`
- matched: `2438F9B04D7CF823C0B0BAB39930CD27`
- **missing**: ` and an RDP bitmap cache at `
- claim: > rsydow has a credentials cache on DC at `Users/rsydow/AppData/Local/Microsoft/Credentials/2438F9B04D7CF823C0B0BAB39930CD27` and an RDP bitmap cache at `Users/rsydow/AppData/Local/Microsoft/Terminal Se…

### ✅ verified _(line 258)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `a.exe`
- claim: > Both accounts have `a.exe` in their Temp directories on the tdungan machine, confirming the attacker executed tools under those account contexts. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d57065…
