# Validator Report — iter_3

## Summary

- Total tagged claims:        **47**
  - CONFIRMED:                 36
  - INFERRED:                  4
  - HYPOTHESIS:                0
  - GAP:                       7
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           31 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                0 (some tokens found, some missing)
- ❌ failed:                 0 (no tokens found)
- ❓ unverifiable:           5 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           0 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 86.1%** (31 verified / 36 confirmed)

## LLM-based prose check (v4)

- LLM verdicts collected: **5** (cost: $0.0063)
  - ✅ VERIFIED:    0 (rule-unverifiable → upgraded to verified)
  - ❌ UNSUPPORTED: 0 (downgraded to failed)
  - ❓ UNRELATED:   2 (cited tool not relevant — kept unverifiable)
  - ❓ UNCERTAIN:   3 (genuinely ambiguous — kept unverifiable)

## Per-claim verdicts

### ❓ unverifiable _(line 49)_
- exec_ids: `56eb712b06e2`, `2e25aa9a719c`, `2c0f865472a5`, `efacda3f01c5`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — The claim references specific execution IDs (exec_id values) which are process or activity tracking identifiers, but ewf_info provides only disk image metadata (acquisition details, hashes, sector counts) with no execution or process tracking data.
- claim: > [CONFIRMED — exec_id 019e10f1-fc74-7ba1-9cd4-56eb712b06e2, exec_id 019e10f1-ff4f-7d71-b106-2e25aa9a719c, exec_id 019e10f2-00de-71c3-9c71-2c0f865472a5, exec_id 019e10f2-02bb-7842-a5dd-efacda3f01c5]

### ✅ verified _(line 57)_
- tools: `tsk_fls_list`
- exec_ids: `59dc487be0a4`
- matched: `adberdr813.exe`, `Users/nromanoff/Downloads/adberdr813.exe`, `:Zone.Identifier`
- claim: > `adberdr813.exe` (Adobe Reader 8.1.3 trojanized installer) present at `Users/nromanoff/Downloads/adberdr813.exe` with NTFS Alternate Data Stream `:Zone.Identifier` confirming internet browser download…

### ✅ verified _(line 61)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `AdbeRdr910_en_US.exe`
- claim: > `AdbeRdr910_en_US.exe` (Adobe Reader 9.1.0 trojanized installer) was delivered via Dropbox and logged in the Dropbox cache: `Documents and Settings/tdungan/My Documents/Dropbox/.dropbox.cache/2012-04-…

### ✅ verified _(line 63)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `ADBERDR910_EN_US.EXE`, `-2CFF2AE5.pf`, `WINDOWS/Prefetch/ADBERDR910_EN_US.EXE-2CFF2AE5.pf`
- claim: > Prefetch `WINDOWS/Prefetch/ADBERDR910_EN_US.EXE-2CFF2AE5.pf` confirms execution of the trojanized installer. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### ✅ verified _(line 75)_
- tools: `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`
- matched: `74541`, `NTUSER.DAT`, `vibranium`, `S-1-5-21-2036804247-3058324640-2116585241-1673`, `Users/vibranium/NTUSER.DAT`
- claim: > The `vibranium` domain account (SID: `S-1-5-21-2036804247-3058324640-2116585241-1673`) had an active RDP session on the DC at capture time (established from prior memory run). Disk confirms the vibran…

### ✅ verified _(line 79)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `4cf3be7f7746`, `78b9e9842308`, `59dc487be0a4`, `d40d5706591a`
- matched: `7793`, `60927`, `spinlock.exe`, `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`, `Windows/System32/spinlock.exe`, `spinlock.exe.manifest`, `_MEI`, `WINDOWS/system32/spinlock.exe`
- claim: > `spinlock.exe` (SHA256: `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`, 2,271,885 bytes) deployed identically to **nromanoff** at `Windows/System32/spinlock.exe` (inode 60927) and …

### ✅ verified _(line 81)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `dcdae4929196`, `c60439c821bf`, `59dc487be0a4`, `d40d5706591a`
- matched: `4736`, `60958`, `hydrakatz.exe`, `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975`, `Windows/System32/hydrakatz.exe`, `WINDOWS/system32/hydrakatz.exe`
- claim: > `hydrakatz.exe` (SHA256: `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975`, 548,848 bytes) deployed identically to **nromanoff** at `Windows/System32/hydrakatz.exe` (inode 60958) and …

### ✅ verified _(line 85)_
- tools: `tsk_fls_list`
- exec_ids: `59dc487be0a4`
- matched: `-51BA46F2.pf`, `PSEXESVC.EXE`, `Windows/Prefetch/PSEXESVC.EXE-51BA46F2.pf`
- claim: > `Windows/Prefetch/PSEXESVC.EXE-51BA46F2.pf` on nromanoff confirms the PSExec service binary was executed on this host. [CONFIRMED — exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4]

### ✅ verified _(line 91)_
- tools: `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `59dc487be0a4`, `d40d5706591a`
- matched: `a.exe`, `Temp`, `Documents and Settings/vibranium/Local Settings/Temp/a.exe`, `Users/vibranium/AppData/Local/Temp/a.exe`
- claim: > The vibranium domain account's `Temp` directory contains `a.exe` on both **nromanoff** (`Users/vibranium/AppData/Local/Temp/a.exe`) and **tdungan** (`Documents and Settings/vibranium/Local Settings/Te…

### ✅ verified _(line 95)_
- tools: `tsk_fls_list`
- exec_ids: `59dc487be0a4`
- matched: `rsydow`, `nromanoff`, `vibranium`, `SRL-Helpdesk`, `Tdungan`
- claim: > Profiles present on nromanoff: `nromanoff`, `rsydow`, `SRL-Helpdesk`, `Tdungan`, `vibranium` — all as interactive logins. This breadth indicates successful credential harvest and reuse across the doma…

### ✅ verified _(line 99)_
- tools: `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`
- matched: `58544`, `NTUSER.DAT`, `Users/tdungan/NTUSER.DAT`
- claim: > `Users/tdungan/NTUSER.DAT` (inode 58544) is present on the DC disk, proving tdungan authenticated to the Domain Controller post-compromise. [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b]

### ❓ unverifiable _(line 103)_
- exec_ids: `2c0f865472a5`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNRELATED** — ewf_info provides only image acquisition metadata (hash, size, format, case details) and contains no data about processes, binaries, tools, or profiles that would support or refute claims about attack tools or suspicious executables on the system.
- claim: > No attack tools, no vibranium profile, no suspicious binaries found on nfury. [CONFIRMED — exec_id 019e10f2-00de-71c3-9c71-2c0f865472a5 (negative finding)]

### ❓ unverifiable _(line 115)_
- exec_ids: `e9e4fe2b1f8b`, `00e925f580bb`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The claim consists only of execution IDs with no testable factual assertion; the parsed data contains file system metadata aggregates with no execution ID fields, making structural comparison impossible.
- claim: > [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b, exec_id 019e10f4-da1b-7770-b9d2-00e925f580bb]

### ✅ verified _(line 117)_
- tools: `vol3_netscan`, `tsk_fls_list`, `tsk_icat_extract`
- exec_ids: `aff5c2a65f83`, `e9e4fe2b1f8b`, `00e925f580bb`
- matched: `27304`, `96.255.98.154`, `usboesrv.exe`, `29932`
- claim: > The System32 copy is the live C2 implant. DC netscan confirms three simultaneous ESTABLISHED TCPv4 connections from `usboesrv.exe` (PID 27304) to foreign address `96.255.98.154`, foreign port `29932` …

### ✅ verified _(line 119)_
- tools: `tsk_fls_list`, `tsk_icat_extract`
- exec_ids: `e9e4fe2b1f8b`, `00e925f580bb`
- matched: `usb-over-ethernet.zip`, `usboesrv.exe`, `setup.exe`, `Temp1_usb-over-ethernet.zip`, `Users/rsydow/AppData/Local/Temp/2/Temp1_usb-over-ethernet.zip/`, `rsydow`, `SharedFolders/Public/Security Tools/usb-over-ethernet.zip`
- claim: > Installer chain: `SharedFolders/Public/Security Tools/usb-over-ethernet.zip` → extracted by `rsydow` to `Users/rsydow/AppData/Local/Temp/2/Temp1_usb-over-ethernet.zip/` → `setup.exe` from the zip inst…

### ✅ verified _(line 123)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `4cf3be7f7746`, `78b9e9842308`, `59dc487be0a4`, `d40d5706591a`
- matched: `7793`, `60927`, `spinlock.exe`, `WINDOWS/system32/spinlock.exe`, `_MEI`, `spinlock.exe.manifest`, `Windows/System32/spinlock.exe`
- claim: > `Windows/System32/spinlock.exe` (inode 60927) on nromanoff and `WINDOWS/system32/spinlock.exe` (inode 7793) on tdungan are present on disk. PyInstaller-bundled binary confirmed by `_MEI` temp extracti…

### ✅ verified _(line 125)_
- tools: `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`
- matched: `spinlock.exe`
- claim: > On DC, spinlock.exe was sdeleted. WER crash artifacts survive at `ProgramData/Microsoft/Windows/WER/ReportQueue/NonCritical_spinlock.exe_f55bbffa8ebc6a99e6cbf535420484d134edcb1_cab_436b9004/Report.wer…

### ✅ verified _(line 129)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `dcdae4929196`, `c60439c821bf`, `59dc487be0a4`, `d40d5706591a`
- matched: `4736`, `60958`, `-27B49502.pf`, `-A0DADA85.pf`, `HYDRAKATZ.EXE`, `hydrakatz.exe`, `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975`, `Windows/System32/hydrakatz.exe` (+3 more)
- claim: > Deployed to `Windows/System32/hydrakatz.exe` on nromanoff (inode 60958) and `WINDOWS/system32/hydrakatz.exe` on tdungan (inode 4736). Identical SHA256 `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d…

### ✅ verified _(line 133)_
- tools: `tsk_icat_extract`, `tsk_fls_list`
- exec_ids: `577d551822de`, `59dc487be0a4`
- matched: `9628`, `-4EFD8FD3.pf`, `TopLZAGU.exe`, `TOPLZAGU.EXE`, `0c8439344e9e2c8cbac86092ec96711c82545d71e9e3f4a1d41e8c4ebd2884c9`, `Windows/TopLZAGU.exe`, `TOPLZAGU.EXE-4EFD8FD3.pf`
- claim: > `Windows/TopLZAGU.exe` (inode 9628) on nromanoff is located in the Windows root directory, outside the standard System32 location used by legitimate OS components. SHA256: `0c8439344e9e2c8cbac86092ec9…

### ✅ verified _(line 137)_
- tools: `tsk_icat_extract`, `tsk_fls_list`
- exec_ids: `b986e0ebbf12`, `d40d5706591a`
- matched: `5237`, `-2A94EF14.pf`, `HYVY.EXE`, `hyvy.exe`, `spinlock.exe`, `5a31b6aae73fdfe211c90370f3d7369846ec55fa2de8f20fd2e35368c1070232`, `WINDOWS/system32/hyvy.exe`, `HYVY.EXE-2A94EF14.pf`
- claim: > `WINDOWS/system32/hyvy.exe` (inode 5237) on tdungan has a Zone.Identifier ADS confirming it was downloaded from the internet. SHA256: `5a31b6aae73fdfe211c90370f3d7369846ec55fa2de8f20fd2e35368c1070232`…

### ✅ verified _(line 141)_
- tools: `tsk_icat_extract`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `4aad78c0091c`, `d40d5706591a`, `59dc487be0a4`
- matched: `a.exe`, `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec`, `Users/vibranium/AppData/Local/Temp/`
- claim: > On tdungan, `a.exe` (9,216 bytes, SHA256: `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec`) executed under four user accounts: RSydow, SRL-Helpdesk, tdungan, and vibranium (each has …

### ✅ verified _(line 145)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `3019`, `pkxezy1tji98.exe`, `Documents and Settings/tdungan/Local Settings/Temp/pkxezy1tji98.exe`
- claim: > `Documents and Settings/tdungan/Local Settings/Temp/pkxezy1tji98.exe` (inode 3019). Random alphanumeric filename is a classic malware staging pattern. Prefetch confirms execution. [CONFIRMED — exec_id…

### ✅ verified _(line 149)_
- tools: `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`
- matched: `bcwipe5.exe`, `spinlock.exe`, `SharedFolders/Public/Security Tools/BC Wipe/bcwipe5.exe`
- claim: > `SharedFolders/Public/Security Tools/BC Wipe/bcwipe5.exe` present on DC shared network location, available to all domain hosts. This tool accounts for sdeleted spinlock.exe and other cleaned artifacts…

### ✅ verified _(line 153)_
- tools: `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`
- matched: `usboesrv.exe`
- claim: > No attacker binaries found in user Startup folders on DC, nromanoff, or tdungan. Persistence for `usboesrv.exe` was via service registration (confirmed in prior memory run via svcscan). [CONFIRMED — e…

### ❓ unverifiable _(line 173)_
- exec_ids: `d40d5706591a`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The claim contains only an execution identifier with no specific factual assertion about file system contents, so there is nothing to structurally verify or contradict against the file listing data provided.
- claim: > [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### ✅ verified _(line 177)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `CC-Backstopped-Accounts.xlsx`, `Credit-Card-Numbers-For-Research.xls`, ` and `
- claim: > `Documents and Settings/tdungan/My Documents/Backstopped Accounts - R&D Costs Alloy Research/Credit-Card-Numbers-For-Research.xls` and `CC-Backstopped-Accounts.xlsx` are present on tdungan's disk. [CO…

### ✅ verified _(line 179)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `Credit-Card-Numbers-For-Research.xlsx`
- claim: > `Credit-Card-Numbers-For-Research.xlsx` is additionally present at `Documents and Settings/tdungan/Local Settings/Temporary Internet Files/Content.Outlook/CNGZG4QC/`, the standard Office email attachm…

### ✅ verified _(line 185)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `Labs.docx`, `-126FAE33.pf`, `CCleaner.exe`, `DROPBOX.EXE`, `Documents and Settings/tdungan/Application Data/Dropbox/`, `Documents and Settings/tdungan/My Documents/Dropbox/STARK Research Labs.docx`, `DROPBOX.EXE-126FAE33.pf`
- claim: > Dropbox installed at `Documents and Settings/tdungan/Application Data/Dropbox/`. The attacker staged `Documents and Settings/tdungan/My Documents/Dropbox/STARK Research Labs.docx` in the Dropbox sync …

### ✅ verified _(line 189)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `-0FFFB5A3.pf`, `FTP.EXE`, `-2C9C69B1.pf`, `ZIPPER.EXE`, `WINDOWS/Prefetch/FTP.EXE-0FFFB5A3.pf`, `WINDOWS/Prefetch/ZIPPER.EXE-2C9C69B1.pf`
- claim: > `WINDOWS/Prefetch/ZIPPER.EXE-2C9C69B1.pf` on tdungan — file archiver executed (binary sdeleted, Prefetch survives). `WINDOWS/Prefetch/FTP.EXE-0FFFB5A3.pf` on tdungan — Windows native FTP client execut…

### ✅ verified _(line 193)_
- tools: `vol3_netscan`
- exec_ids: `aff5c2a65f83`
- matched: `27304`, `96.255.98.154`, `usboesrv.exe`, `29932`
- claim: > `usboesrv.exe` on DC maintained three simultaneous persistent TCP connections to foreign address `96.255.98.154`, foreign port `29932` (ESTABLISHED at capture time, PID 27304, local ports 58495, 58496…

### ❓ unverifiable _(line 212)_
- exec_ids: `e9e4fe2b1f8b`, `59dc487be0a4`, `d40d5706591a`, `aff5c2a65f83`
- note: claim has no extractable tokens (prose only)
- LLM check: **UNCERTAIN** — The claim contains only execution IDs without any specific factual assertion about file system contents, and the parsed data provides file statistics without any matching execution ID references, making the claim's substance non-evaluable against this tool's data.
- claim: > [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b, exec_id 019e10f2-80ec-7560-baf3-59dc487be0a4, exec_id 019e10f2-bedf-7473-9710-d40d5706591a, exec_id 019e10fa-e7bf-7e33-8377-aff5c2a65f83]

### ✅ verified _(line 220)_
- tools: `tsk_fls_list`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`, `59dc487be0a4`, `d40d5706591a`
- matched: `a.exe`, `S-1-5-21-2036804247-3058324640-2116585241-1673`, `Documents and Settings/vibranium/Application Data/Microsoft/Protect/`
- claim: > SID `S-1-5-21-2036804247-3058324640-2116585241-1673`. DPAPI Protect keys on DC and on tdungan at `Documents and Settings/vibranium/Application Data/Microsoft/Protect/`. Interactive sessions confirmed …

### ✅ verified _(line 224)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `dcdae4929196`, `c60439c821bf`, `59dc487be0a4`, `d40d5706591a`
- matched: `4736`, `60958`, `hydrakatz.exe`, `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975`, `Windows/System32/hydrakatz.exe`, `WINDOWS/system32/hydrakatz.exe`
- claim: > `Windows/System32/hydrakatz.exe` on nromanoff (inode 60958) and `WINDOWS/system32/hydrakatz.exe` on tdungan (inode 4736), identical SHA256 `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a…

### ✅ verified _(line 228)_
- tools: `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`
- matched: `2438F9B04D7CF823C0B0BAB39930CD27`
- claim: > rsydow has a credentials cache on DC at `Users/rsydow/AppData/Local/Microsoft/Credentials/2438F9B04D7CF823C0B0BAB39930CD27` (inode confirmed in DC fls). [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9…

### ✅ verified _(line 230)_
- tools: `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`
- matched: `73939`, `Users/rsydow/AppData/Local/Microsoft/Terminal Server Client/Cache/bcache22.bmc`
- claim: > An RDP bitmap cache exists on DC at `Users/rsydow/AppData/Local/Microsoft/Terminal Server Client/Cache/bcache22.bmc` (inode 73939), indicating RDP connections were made from the DC under rsydow's acco…

### ✅ verified _(line 234)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `a.exe`
- claim: > Both accounts have `a.exe` in their Temp directories on the tdungan machine, confirming the attacker executed tools under those account contexts. [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d57065…
