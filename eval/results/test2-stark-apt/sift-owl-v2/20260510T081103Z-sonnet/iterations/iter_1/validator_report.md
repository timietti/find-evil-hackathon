# Validator Report — iter_1

## Summary

- Total tagged claims:        **37**
  - CONFIRMED:                 29
  - INFERRED:                  1
  - HYPOTHESIS:                0
  - GAP:                       7
  - other:                     0

## Verification of CONFIRMED claims

- ✅ **verified:**           13 (every extracted token found in cited tool's parsed output)
- ⚠ partial:                9 (some tokens found, some missing)
- ❌ failed:                 2 (no tokens found)
- ❓ unverifiable:           5 (claim is prose only, no extractable tokens)
- 🔍 exec_id_not_found:     0 (cited exec_id is not in the audit log)
- ⛔ tool_not_supported:    0 (no parser for cited tool)
- ⚠ not_confirmed:           0 (CONFIRMED-tagged but missing exec_id)

**Confirmation score: 44.8%** (13 verified / 29 confirmed)

## Per-claim verdicts

### ❓ unverifiable _(line 42)_
- exec_ids: `56eb712b06e2`, `2e25aa9a719c`, `2c0f865472a5`, `efacda3f01c5`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e10f1-fc74-7ba1-9cd4-56eb712b06e2, 019e10f1-ff4f-7d71-b106-2e25aa9a719c, 019e10f2-00de-71c3-9c71-2c0f865472a5, 019e10f2-02bb-7842-a5dd-efacda3f01c5]

### ✅ verified _(line 50)_
- tools: `tsk_fls_list`
- exec_ids: `59dc487be0a4`
- matched: `adberdr813.exe`, `:Zone.Identifier`, `Users/nromanoff/Downloads/adberdr813.exe`
- claim: > `adberdr813.exe` (Adobe Reader 8.1.3 trojanized installer) present at `Users/nromanoff/Downloads/adberdr813.exe` with NTFS Alternate Data Stream `:Zone.Identifier` confirming internet browser download…

### ⚠ partial _(line 54)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `-2CFF2AE5.pf`, `AdbeRdr910_en_US.exe`, `ADBERDR910_EN_US.EXE`
- **missing**: `0x4f799e4f`, `. The filename encodes the deletion timestamp `, ` = 2012-04-02 UTC. Prefetch `
- claim: > `AdbeRdr910_en_US.exe` (Adobe Reader 9.1.0 trojanized installer) was delivered via Dropbox: found in `Documents and Settings/tdungan/My Documents/Dropbox/.dropbox.cache/2012-04-02/AdbeRdr910_en_US (de…

### ✅ verified _(line 64)_
- tools: `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`
- matched: `74541`, `NTUSER.DAT`, `vibranium`, `S-1-5-21-2036804247-3058324640-2116585241-1673`, `Users/vibranium/NTUSER.DAT`
- claim: > From the previous memory-only run: the `vibranium` domain account (SID: `S-1-5-21-2036804247-3058324640-2116585241-1673`) had an active RDP session on the DC at capture time. Disk confirms the vibrani…

### ⚠ partial _(line 68)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`
- exec_ids: `4cf3be7f7746`, `78b9e9842308`
- matched: `7793`, `60927`, `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`
- **missing**: `spinlock.exe`, `WINDOWS/system32/spinlock.exe`, `Windows/System32/spinlock.exe`
- claim: > `spinlock.exe` (SHA256: `6eef2381040cd38ce5974ef954121e136bd93ec4039d49925438c92ef5f3dead`, 2,271,885 bytes) deployed identically on **both nromanoff** (`Windows/System32/spinlock.exe`, inode 60927) *…

### ⚠ partial _(line 70)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`
- exec_ids: `dcdae4929196`, `c60439c821bf`
- matched: `60958`, `4736`, `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975`
- **missing**: `hydrakatz.exe`, `WINDOWS/system32/hydrakatz.exe`, `Windows/System32/hydrakatz.exe`
- claim: > `hydrakatz.exe` (SHA256: `92d24128a45f33bdca5f28eb0319668cb97fb2f8a7e7b72d70a3aa4c897a4975`, 548,848 bytes) deployed identically on **nromanoff** (`Windows/System32/hydrakatz.exe`, inode 60958) **and …

### ⚠ partial _(line 74)_
- tools: `tsk_fls_list`
- exec_ids: `59dc487be0a4`
- matched: `PSEXESVC.EXE`, `-51BA46F2.pf`, `Windows/Prefetch/PSEXESVC.EXE-51BA46F2.pf`
- **missing**: `psexec`
- claim: > `Windows/Prefetch/PSEXESVC.EXE-51BA46F2.pf` on nromanoff confirms the PSExec service binary ran on this host — consistent with the attacker deploying tools via `psexec` from another compromised host. …

### ✅ verified _(line 78)_
- tools: `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `59dc487be0a4`, `d40d5706591a`
- matched: `spinlock.exe`, `a.exe`, `Documents and Settings/vibranium/Local Settings/Temp/a.exe`, `Users/vibranium/AppData/Local/Temp/a.exe`
- claim: > The vibranium domain account has local Temp artifacts on **nromanoff** (`Users/vibranium/AppData/Local/Temp/a.exe`) and **tdungan** (`Documents and Settings/vibranium/Local Settings/Temp/a.exe`). Also…

### ✅ verified _(line 82)_
- tools: `tsk_fls_list`
- exec_ids: `59dc487be0a4`
- matched: `Tdungan`, `rsydow`, `nromanoff`, `SRL-Helpdesk`, `vibranium`
- claim: > Profiles present on nromanoff: `nromanoff`, `rsydow`, `SRL-Helpdesk`, `Tdungan`, `vibranium` — all as interactive logins. This breadth of credential reuse indicates successful credential harvest and u…

### ✅ verified _(line 86)_
- tools: `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`
- matched: `58544`, `NTUSER.DAT`, `Users/tdungan/NTUSER.DAT`, `tdungan`
- claim: > Users `tdungan` has a full interactive profile (`Users/tdungan/NTUSER.DAT`, inode 58544) on the DC disk, proving tdungan authenticated to the Domain Controller post-compromise. [CONFIRMED — exec_id 01…

### ❓ unverifiable _(line 90)_
- exec_ids: `2c0f865472a5`
- note: claim has no extractable tokens (prose only)
- claim: > No attack tools, no vibranium profile, no suspicious binaries found on nfury. [CONFIRMED — exec_id 019e10f2-00de-71c3-9c71-2c0f865472a5 (negative finding)]

### ⚠ partial _(line 102)_
- tools: `tsk_fls_list`, `tsk_icat_extract`
- exec_ids: `e9e4fe2b1f8b`, `00e925f580bb`
- matched: `usb-over-ethernet.zip`, `setup.exe`, `Temp1_usb-over-ethernet.zip`, `usboesrv.exe`, `Users/rsydow/AppData/Local/Temp/2/Temp1_usb-over-ethernet.zip/`, `rsydow`, `SharedFolders/Public/Security Tools/usb-over-ethernet.zip`
- **missing**: `96.255.98.154`, `96.255.98.154:29932`
- claim: > The System32 copy is the live C2 implant (confirmed in memory run: active connections to `96.255.98.154:29932`). The installer chain was: `SharedFolders/Public/Security Tools/usb-over-ethernet.zip` → …

### ⚠ partial _(line 106)_
- tools: `tsk_fls_list`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`, `59dc487be0a4`, `d40d5706591a`
- matched: `spinlock.exe`, `_MEI`, `spinlock.exe.manifest`
- **missing**: `ProgramData/Microsoft/Windows/WER/ReportQueue/NonCritical_spinlock.exe_f55bb…/`
- claim: > Present in system32 on both nromanoff (not deleted) and tdungan (not deleted). PyInstaller-bundled binary (confirmed by `_MEI` temp extraction directories with `spinlock.exe.manifest` files). On DC, s…

### ❌ failed _(line 110)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`
- exec_ids: `dcdae4929196`, `c60439c821bf`
- **missing**: `hydrakatz.exe`, `WINDOWS/system32/hydrakatz.exe`, `Windows/System32/hydrakatz.exe`
- claim: > Deployed to `WINDOWS/system32/hydrakatz.exe` on tdungan and `Windows/System32/hydrakatz.exe` on nromanoff. Prefetch confirms execution on both hosts. Identical SHA256 across both hosts. [CONFIRMED — e…

### ⚠ partial _(line 114)_
- tools: `tsk_icat_extract`, `tsk_fls_list`
- exec_ids: `577d551822de`, `59dc487be0a4`
- matched: `-4EFD8FD3.pf`, `0c8439344e9e2c8cbac86092ec96711c82545d71e9e3f4a1d41e8c4ebd2884c9`, `TOPLZAGU.EXE-4EFD8FD3.pf`
- 🚨 negation violations (claimed absent but found): `9628`, `TOPLZAGU.EXE`, `TopLZAGU.exe`, `Windows/TopLZAGU.exe`
- claim: > `Windows/TopLZAGU.exe` (inode 9628) on nromanoff at Windows root level (unusual location — not System32). SHA256: `0c8439344e9e2c8cbac86092ec96711c82545d71e9e3f4a1d41e8c4ebd2884c9`, 15,872 bytes. The …

### ✅ verified _(line 118)_
- tools: `tsk_icat_extract`, `tsk_fls_list`
- exec_ids: `b986e0ebbf12`, `d40d5706591a`
- matched: `5237`, `spinlock.exe`, `HYVY.EXE`, `hyvy.exe`, `-2A94EF14.pf`, `5a31b6aae73fdfe211c90370f3d7369846ec55fa2de8f20fd2e35368c1070232`, `WINDOWS/system32/hyvy.exe`, `HYVY.EXE-2A94EF14.pf`
- claim: > `WINDOWS/system32/hyvy.exe` (inode 5237) on tdungan has Zone.Identifier ADS (internet-downloaded file), SHA256: `5a31b6aae73fdfe211c90370f3d7369846ec55fa2de8f20fd2e35368c1070232`, 2,277,805 bytes. Siz…

### ✅ verified _(line 122)_
- tools: `tsk_icat_extract`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `4aad78c0091c`, `d40d5706591a`, `59dc487be0a4`
- matched: `-0FBE37C1.pf`, `a.exe`, `-0F3A0E12.pf`, `A.EXE`, `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec`, `A.EXE-0FBE37C1.pf`, `Users/vibranium/AppData/Local/Temp/`, `A.EXE-0F3A0E12.pf`
- claim: > On tdungan, `a.exe` (9,216 bytes, SHA256: `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec`) found in Temp directories for **four different users**: RSydow, SRL-Helpdesk, tdungan, and…

### ✅ verified _(line 126)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `3019`, `pkxezy1tji98.exe`, `Documents and Settings/tdungan/Local Settings/Temp/pkxezy1tji98.exe`
- claim: > `Documents and Settings/tdungan/Local Settings/Temp/pkxezy1tji98.exe` (inode 3019). The random alphanumeric name is a classic malware staging pattern. Prefetch confirms execution. [CONFIRMED — exec_id…

### ❓ unverifiable _(line 130)_
- exec_ids: `e9e4fe2b1f8b`
- note: claim has no extractable tokens (prose only)
- claim: > No attacker binaries found in user Startup folders on DC, nromanoff, or tdungan. Persistence for usboesrv was via service registration (confirmed in prior memory run via svcscan). [CONFIRMED — exec_id…

### ✅ verified _(line 134)_
- tools: `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`
- matched: `spinlock.exe`, `bcwipe5.exe`, `SharedFolders/Public/Security Tools/BC Wipe/bcwipe5.exe`
- claim: > `SharedFolders/Public/Security Tools/BC Wipe/bcwipe5.exe` present on DC shared network location, available to all domain hosts. This explains sdeleted spinlock.exe and other file removals. [CONFIRMED …

### ❓ unverifiable _(line 154)_
- exec_ids: `d40d5706591a`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e10f2-bedf-7473-9710-d40d5706591a]

### ⚠ partial _(line 158)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `CC-Backstopped-Accounts.xlsx`, `Credit-Card-Numbers-For-Research.xls`, `Credit-Card-Numbers-For-Research.xlsx`, ` and `
- **missing**: ` was also found in `, ` accessed by tdungan. Critically, `
- claim: > `Documents and Settings/tdungan/My Documents/Backstopped Accounts - R&D Costs Alloy Research/Credit-Card-Numbers-For-Research.xls` and `CC-Backstopped-Accounts.xlsx` accessed by tdungan. Critically, `…

### ✅ verified _(line 162)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `CCleaner.exe`, `Labs.docx`, `DROPBOX.EXE`, `-126FAE33.pf`, `Documents and Settings/tdungan/My Documents/Dropbox/STARK Research Labs.docx`, `Documents and Settings/tdungan/Application Data/Dropbox/`, `DROPBOX.EXE-126FAE33.pf`
- claim: > Dropbox was installed under `Documents and Settings/tdungan/Application Data/Dropbox/`. The attacker staged `Documents and Settings/tdungan/My Documents/Dropbox/STARK Research Labs.docx` directly in t…

### ✅ verified _(line 166)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `-0FFFB5A3.pf`, `ZIPPER.EXE`, `-2C9C69B1.pf`, `FTP.EXE`, `WINDOWS/Prefetch/FTP.EXE-0FFFB5A3.pf`, `WINDOWS/Prefetch/ZIPPER.EXE-2C9C69B1.pf`
- claim: > `WINDOWS/Prefetch/ZIPPER.EXE-2C9C69B1.pf` on tdungan — a file archiving tool was run (binary sdeleted but Prefetch survives). `WINDOWS/Prefetch/FTP.EXE-0FFFB5A3.pf` on tdungan — native Windows FTP cli…

### ❓ unverifiable _(line 188)_
- exec_ids: `e9e4fe2b1f8b`, `59dc487be0a4`, `d40d5706591a`
- note: claim has no extractable tokens (prose only)
- claim: > [CONFIRMED — exec_id 019e10f2-232c-7363-b17c-e9e4fe2b1f8b, 019e10f2-80ec-7560-baf3-59dc487be0a4, 019e10f2-bedf-7473-9710-d40d5706591a]

### ✅ verified _(line 195)_
- tools: `tsk_fls_list`, `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`, `59dc487be0a4`, `d40d5706591a`
- matched: `a.exe`, `S-1-5-21-2036804247-3058324640-2116585241-1673`, `Documents and Settings/vibranium/Application Data/Microsoft/Protect/`
- claim: > ### vibranium domain account (primary attacker account) SID `S-1-5-21-2036804247-3058324640-2116585241-1673`. DPAPI Protect keys present on DC and on tdungan under `Documents and Settings/vibranium/Ap…

### ❌ failed _(line 198)_
- tools: `tsk_icat_extract`, `tsk_icat_extract`
- exec_ids: `dcdae4929196`, `c60439c821bf`
- **missing**: `hydrakatz.exe`
- claim: > ### hydrakatz.exe — credential stealer deployed to nromanoff and tdungan Credential harvesting tool present on both hosts (same binary). Credentials harvested from these workstations would include: nr…

### ⚠ partial _(line 201)_
- tools: `tsk_fls_list`, `tsk_fls_list`
- exec_ids: `e9e4fe2b1f8b`, `59dc487be0a4`
- matched: `2438F9B04D7CF823C0B0BAB39930CD27`
- **missing**: `) and a Terminal Server Client RDP bitmap cache (`
- claim: > ### rsydow credentials abused on multiple hosts rsydow has a credentials cache on DC (`Users/rsydow/AppData/Local/Microsoft/Credentials/2438F9B04D7CF823C0B0BAB39930CD27`) and a Terminal Server Client …

### ✅ verified _(line 204)_
- tools: `tsk_fls_list`
- exec_ids: `d40d5706591a`
- matched: `a.exe`
- claim: > ### SRL-Helpdesk and tdungan accounts abused Both have `a.exe` in their Temp dirs on the tdungan machine, indicating the attacker executed tools under those account contexts. [CONFIRMED — exec_id 019e…
